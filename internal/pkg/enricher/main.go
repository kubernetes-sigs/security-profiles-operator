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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/cirocosta/dmesg_exporter/kmsg"
	"github.com/cirocosta/dmesg_exporter/reader"
	"github.com/go-logr/logr"
)

var (
	logFile = "/dev/kmsg"
	logger  logr.Logger
)

// Run the log-enricher to scrap audit logs and enrich them with
// Kubernetes data (namespace, pod and container).
func Run(l logr.Logger) {
	logger = l
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Error(nil, "'NODE_NAME' environment variable not found")
		os.Exit(1)
	}

	logger.V(1).Info("starting log-exporter on node: ", nodeName)

	auditLines := make(chan string)
	go tailDevice(logFile, auditLines)

	for {
		line := <-auditLines

		if !isAuditLine(line) {
			continue
		}

		auditLine, err := extractAuditLine(line)
		if err != nil {
			fmt.Printf("extract seccomp details from audit line: %v\n", err)
		}

		if auditLine.SystemCallID == 0 {
			continue
		}

		cID := getContainerID(auditLine.ProcessID)
		containers, err := getNodeContainers(nodeName)
		c, found := containers[cID]

		if !found {
			logger.Error(err, "containerID not found", "processID", auditLine.ProcessID)
			continue
		}

		name := systemCalls[auditLine.SystemCallID]
		fmt.Printf("audit(%s) type=%s node=%s pid=%d ns=%s pod=%s c=%s exe=%s scid=%d scname=%s\n",
			auditLine.TimestampID, auditLine.Type, nodeName,
			auditLine.ProcessID, c.Namespace, c.PodName,
			c.ContainerName, auditLine.Executable, auditLine.SystemCallID, name)
	}
}

func blockAndCancelOnSignal(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	<-sigChan

	cancel()
}

func tailDevice(device string, msgs chan string) {
	file, err := os.Open(device)
	if err != nil {
		return
	}
	defer file.Close()

	// seek to the end of device
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go blockAndCancelOnSignal(cancel)

	var (
		r        = reader.NewReader(file)
		messages = make(chan *kmsg.Message, 1)
	)

	kmsgErrorsChan := r.Listen(ctx, messages)

	for {
		select {
		case <-kmsgErrorsChan:
			return
		case <-ctx.Done():
			return
		case message := <-messages:
			if message == nil {
				return
			}

			if message.Facility != kmsg.FacilityKern {
				continue
			}

			msgs <- message.Message
		}
	}
}

func getContainerID(processID int) string {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", processID)
	file, err := os.Open(filepath.Clean(cgroupFile))
	if err != nil {
		logger.Error(nil, "could not open cgroup", "process-id", processID)
		return ""
	}
	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	// extracts crio format from cgroup:
	// 0::/system.slice/crio-conmon-5819a498721cf8bb7e334809c9e48aa310bfc98801eb8017034ad17fb0749920.scope
	podIDRegex := regexp.MustCompile(`^0.+-([a-f0-9]+)\.scope$`)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		capture := podIDRegex.FindStringSubmatch(scanner.Text())
		if len(capture) > 0 {
			return capture[1]
		}
	}
	return ""
}
