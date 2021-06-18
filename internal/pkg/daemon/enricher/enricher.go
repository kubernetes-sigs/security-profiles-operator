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
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/hpcloud/tail"
	"github.com/pkg/errors"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

	// If the file does not exist, then tail will wait for it to appear
	tailFile, err := tail.TailFile(
		config.AuditLogPath,
		tail.Config{
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

		if auditLine.SystemCallID == 0 {
			logger.Info("Audit line SystemCallID is 0, skipping")
			continue
		}

		cID := getContainerID(logger, auditLine.ProcessID)
		containers, err := getNodeContainers(nodeName)
		c, found := containers[cID]

		if !found {
			logger.Error(err, "containerID not found", "processID", auditLine.ProcessID)
			continue
		}

		name := systemCalls[auditLine.SystemCallID]
		logger.Info(fmt.Sprintf(
			"audit(%s) type=%s node=%s pid=%d ns=%s pod=%s c=%s exe=%s scid=%d scname=%s",
			auditLine.TimestampID, auditLine.Type, nodeName,
			auditLine.ProcessID, c.Namespace, c.PodName,
			c.ContainerName, auditLine.Executable, auditLine.SystemCallID, name,
		))
	}

	logger.Error(tailFile.Err(), "enricher failed")

	for {
		time.Sleep(time.Second)
	}
}
