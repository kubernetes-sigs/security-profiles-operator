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

	"github.com/ReneKroon/ttlcache/v2"
	"github.com/go-logr/logr"
	"github.com/nxadm/tail"
	"github.com/pkg/errors"

	api "sigs.k8s.io/security-profiles-operator/api/server"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// defaultCacheTimeout is the timeout for the container ID and info cache being
// used. The chosen value is nothing more than a rough guess.
const defaultCacheTimeout time.Duration = time.Hour

// Enricher is the main structure of this package.
type Enricher struct {
	impl             impl
	logger           logr.Logger
	containerIDCache ttlcache.SimpleCache
	infoCache        ttlcache.SimpleCache
}

// New returns a new Enricher instance.
func New(logger logr.Logger) *Enricher {
	return &Enricher{
		impl:             &defaultImpl{},
		logger:           logger,
		containerIDCache: ttlcache.NewCache(),
		infoCache:        ttlcache.NewCache(),
	}
}

// Run the log-enricher to scrap audit logs and enrich them with
// Kubernetes data (namespace, pod and container).
func (e *Enricher) Run() error {
	e.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))
	for _, cache := range []ttlcache.SimpleCache{
		e.containerIDCache, e.infoCache,
	} {
		if err := cache.SetTTL(defaultCacheTimeout); err != nil {
			return errors.Wrap(err, "set cache timeout")
		}
		defer cache.Close()
	}

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

	metricsAuditIncClient, err := e.impl.MetricsAuditInc(client)
	if err != nil {
		return errors.Wrap(err, "create metrics audit client")
	}

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

		cID, err := e.getContainerID(auditLine.processID)
		if err != nil {
			e.logger.Error(err, "unable to get container ID", "processID", auditLine.processID)
			continue
		}

		info, err := e.getContainerInfo(e.logger, nodeName, cID)
		if err != nil {
			e.logger.Error(
				err, "container ID not found in cluster",
				"processID", auditLine.processID,
				"containerID", cID,
			)
			continue
		}

		syscallName := systemCalls[auditLine.systemCallID]
		e.logger.Info("audit",
			"timestamp", auditLine.timestampID,
			"type", auditLine.type_,
			"node", nodeName,
			"namespace", info.namespace,
			"pod", info.podName,
			"container", info.containerName,
			"executable", auditLine.executable,
			"pid", auditLine.processID,
			"syscallID", auditLine.systemCallID,
			"syscallName", syscallName,
		)

		metricsType := api.MetricsAuditRequest_SECCOMP
		if auditLine.type_ == auditTypeSelinux {
			metricsType = api.MetricsAuditRequest_SELINUX
		}
		if err := e.impl.SendMetric(
			metricsAuditIncClient,
			&api.MetricsAuditRequest{
				Type:       metricsType,
				Node:       nodeName,
				Namespace:  info.namespace,
				Pod:        info.podName,
				Container:  info.containerName,
				Executable: auditLine.executable,
				Syscall:    syscallName,
			},
		); err != nil {
			e.logger.Error(err, "unable to update metrics")
		}

		if info.recordProfile != "" {
			if _, err := e.impl.RecordSyscall(
				client,
				&api.RecordSyscallRequest{
					Profile: info.recordProfile,
					Syscall: syscallName,
				},
			); err != nil {
				e.logger.Error(err, "unable to record syscall")
			}
		}
	}

	return errors.Wrap(tailFile.Err(), "enricher failed")
}
