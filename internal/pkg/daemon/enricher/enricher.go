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
	"os"

	"github.com/go-logr/logr"
	"github.com/hpcloud/tail"
	"github.com/pkg/errors"

	api "sigs.k8s.io/security-profiles-operator/api/server"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// Enricher is the main structure of this package.
type Enricher struct {
	impl   impl
	logger logr.Logger
}

// New returns a new Enricher instance.
func New(logger logr.Logger) *Enricher {
	return &Enricher{
		impl:   &defaultImpl{},
		logger: logger,
	}
}

// Run the log-enricher to scrap audit logs and enrich them with
// Kubernetes data (namespace, pod and container).
func (e *Enricher) Run() error {
	nodeName := e.impl.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		err := errors.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")
		return err
	}

	e.logger.Info("Starting log-enricher on node: " + nodeName)

	e.logger.Info("Connecting to local GRPC server")
	conn, err := e.impl.Dial()
	if err != nil {
		return errors.Wrap(err, "connecting to local GRPC server")
	}
	defer e.impl.Close(conn)
	client := api.NewSecurityProfilesOperatorClient(conn)

	// If the file does not exist, then tail will wait for it to appear
	tailFile, err := e.impl.TailFile(
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

	e.logger.Info("Reading from file " + config.AuditLogPath)
	for l := range e.impl.Lines(tailFile) {
		if l.Err != nil {
			e.logger.Error(l.Err, "failed to tail")
			continue
		}

		line := l.Text
		if !isAuditLine(line) {
			continue
		}

		auditLine, err := extractAuditLine(line)
		if err != nil {
			e.logger.Error(err, "extract seccomp details from audit line")
			continue
		}

		cID, err := e.getContainerID(auditLine.ProcessID)
		if err != nil {
			e.logger.Error(err, "unable to get container ID", "processID", auditLine.ProcessID)
			continue
		}

		containers, err := e.getNodeContainers(e.logger, nodeName)
		c, found := containers[cID]

		if !found {
			e.logger.Error(
				err, "containerID not found in cluster",
				"processID", auditLine.ProcessID,
				"containerID", cID,
			)
			continue
		}

		syscallName := systemCalls[auditLine.SystemCallID]
		e.logger.Info("audit",
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
		if _, err := e.impl.MetricsAuditInc(
			client,
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
			e.logger.Error(err, "unable to update metrics")
		}
	}

	return errors.Wrap(tailFile.Err(), "enricher failed")
}
