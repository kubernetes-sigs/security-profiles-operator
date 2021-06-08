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
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
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

	logger.V(1).Info("Starting log-enricher on node: ", nodeName)

	auditLines := make(chan string)
	tailErrors := make(chan error)
	go tailFile(auditLines, tailErrors)

	for {
		var line string
		select {
		case err := <-tailErrors:
			logger.Error(err, "tail audit log")
			return errors.Wrap(err, "tail failed")
		case line = <-auditLines:
		}

		if !isAuditLine(line) {
			continue
		}

		auditLine, err := extractAuditLine(line)
		if err != nil {
			logger.Error(err, "extract seccomp details from audit line")
		}

		if auditLine.SystemCallID == 0 {
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
		logger.Info(fmt.Sprintf("audit(%s) type=%s node=%s pid=%d ns=%s pod=%s c=%s exe=%s scid=%d scname=%s\n",
			auditLine.TimestampID, auditLine.Type, nodeName,
			auditLine.ProcessID, c.Namespace, c.PodName,
			c.ContainerName, auditLine.Executable, auditLine.SystemCallID, name))
	}
}

func tailFile(lines chan string, errChan chan error) {
	file, err := os.Open(filepath.Clean(config.EnricherLogFile))
	if err != nil {
		errChan <- errors.Wrap(err, "open audit log file")
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			errChan <- errors.Wrap(err, "close audit log file")
		}
	}()

	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		errChan <- errors.Wrap(err, "seek end audit log")
		return
	}

	buffer := make([]byte, 1024)
	for {
		readBytes, err := file.ReadAt(buffer, offset)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				errChan <- errors.Wrap(err, "read audit log buffer")
				return
			}
		}
		offset += int64(readBytes)
		if readBytes != 0 {
			lines <- string(buffer[:readBytes])
		}
		time.Sleep(time.Second)
	}
}
