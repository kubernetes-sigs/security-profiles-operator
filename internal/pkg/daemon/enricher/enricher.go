/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package enricher

import (
	"context"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/hpcloud/tail"
	"github.com/pkg/errors"
	"google.golang.org/grpc"

	api "sigs.k8s.io/security-profiles-operator/api/server"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/server"
)

// Run the log-enricher to scrap audit logs and enrich them with
// Kubernetes data (namespace, pod and container).
func Run(logger logr.Logger) error {
	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		err := errors.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		logger.Error(err, "unable to run enricher")
		return err
	}

	logger.Info("Starting log-enricher on node: " + nodeName)

	logger.Info("Connecting to local GRPC server")
	conn, err := grpc.Dial(server.Addr(), grpc.WithInsecure())
	if err != nil {
		return errors.Wrap(err, "connecting to local GRPC server")
	}
	defer conn.Close()
	client := api.NewSecurityProfilesOperatorClient(conn)

	// If the file does not exist, then tail will wait for it to appear
	tailFile, err := tail.TailFile(
		config.AuditLogPath,
		tail.Config{
			ReOpen: true,
			Follow: true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: os.SEEK_END,
			},
		},
	)
	if err != nil {
		return errors.Wrap(err, "tailing file")
	}

	logger.Info("Reading from file " + config.AuditLogPath)
	for l := range tailFile.Lines {
		if l.Err != nil {
			logger.Error(l.Err, "failed to tail")
			continue
		}

		line := l.Text
		if !isAuditLine(line) {
			continue
		}

		auditLine, err := extractAuditLine(line)
		if err != nil {
			logger.Error(err, "extract seccomp details from audit line")
			continue
		}

		cID, err := getContainerID(auditLine.ProcessID)
		if err != nil {
			logger.Error(err, "unable to get container ID", "processID", auditLine.ProcessID)
			continue
		}

		containers, err := getNodeContainers(logger, nodeName)
		c, found := containers[cID]

		if !found {
			logger.Error(
				err, "containerID not found in cluster",
				"processID", auditLine.ProcessID,
				"containerID", cID,
			)
			continue
		}

		syscallName := systemCalls[auditLine.SystemCallID]
		logger.Info("audit",
			"timestamp", auditLine.TimestampID,
			"type", auditLine.Type,
			"node", nodeName,
			"namespace", c.Namespace,
			"pod", c.PodName,
			"container", c.ContainerName,
			"executable", auditLine.Executable,
			"pid", auditLine.ProcessID,
			"syscallID", auditLine.SystemCallID,
			"syscallName", syscallName,
		)

		metricsType := api.MetricsAuditRequest_SECCOMP
		if auditLine.Type == AuditTypeSelinux {
			metricsType = api.MetricsAuditRequest_SELINUX
		}
		if _, err := client.MetricsAuditInc(
			context.Background(),
			&api.MetricsAuditRequest{
				Type:       metricsType,
				Node:       nodeName,
				Namespace:  c.Namespace,
				Pod:        c.PodName,
				Container:  c.ContainerName,
				Executable: auditLine.Executable,
				Syscall:    syscallName,
			},
		); err != nil {
			logger.Error(err, "unable to update metrics")
		}
	}

	logger.Error(tailFile.Err(), "enricher failed")

	for {
		time.Sleep(time.Second)
	}
}
