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
	"sigs.k8s.io/release-utils/util"

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

	auditLines := make(chan string)
	tailErrors := make(chan error)

	logFile := config.EnricherLogFile
	if util.Exists(config.DevKmsgPath) {
		logFile = config.DevKmsgPath
	}
	logger.Info("Reading from file " + logFile)
	go tailFile(logger, logFile, auditLines, tailErrors)

	for {
		var line string
		select {
		case err := <-tailErrors:
			logger.Error(err, "tail audit log")
			return errors.Wrap(err, "failed to tail")
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

func tailFile(logger logr.Logger, filePath string, lines chan string, errChan chan error) {
	file, err := os.Open(filepath.Clean(filePath))
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

	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		errChan <- errors.Wrap(err, "seek end audit log")
		return
	}

	buffer := make([]byte, 1024)
	for {
		readBytes, err := file.Read(buffer)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				errChan <- errors.Wrap(err, "read audit log buffer")
				return
			}
		}
		if readBytes != 0 {
			line := string(buffer[:readBytes])
			logger.Info(line)
			lines <- line
		}
		time.Sleep(time.Second)
	}
}
