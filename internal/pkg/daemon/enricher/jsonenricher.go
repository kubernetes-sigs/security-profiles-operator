/*
Copyright 2025 The Kubernetes Authors.

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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/nxadm/tail"
	"k8s.io/client-go/kubernetes"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

type JsonEnricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	logger           logr.Logger
	containerIDCache *ttlcache.Cache[string, string]
	infoCache        *ttlcache.Cache[string, *types.ContainerInfo]
	logLinesCache    *ttlcache.Cache[int, *types.LogBucket]
	clientset        kubernetes.Interface
	processCache     *ttlcache.Cache[int, *types.ProcessInfo]
	outputFile       *os.File
}

type JsonEnricherOptions struct {
	AuditFreq      time.Duration
	OutputFileName string
}

var JsonEnricherDefaultOptions = JsonEnricherOptions{
	AuditFreq:      time.Duration(60) * time.Second,
	OutputFileName: "",
}

func NewJsonEnricher(logger logr.Logger) (*JsonEnricher, error) {
	return NewJsonEnricherArgs(logger, &JsonEnricherOptions{})
}

var auditLogOutputMutex sync.Mutex

func NewJsonEnricherArgs(logger logr.Logger, opts *JsonEnricherOptions) (*JsonEnricher, error) {
	actualOpts := JsonEnricherDefaultOptions

	if opts != nil {
		if opts.AuditFreq != 0 {
			actualOpts.AuditFreq = opts.AuditFreq
		}

		if opts.OutputFileName != "" { // Check if caller provided a non-zero value
			actualOpts.OutputFileName = ""
		}
	}

	jsonEnricher := &JsonEnricher{
		impl:   &defaultImpl{},
		logger: logger,
		containerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
		),
		logLinesCache: ttlcache.New(
			ttlcache.WithTTL[int, *types.LogBucket](actualOpts.AuditFreq),
			ttlcache.WithCapacity[int, *types.LogBucket](maxCacheItems),
		),
		processCache: ttlcache.New(
			ttlcache.WithTTL[int, *types.ProcessInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[int, *types.ProcessInfo](maxCacheItems),
		),
	}

	if actualOpts.OutputFileName != "" {
		outputFile, err := os.OpenFile(actualOpts.OutputFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}

		jsonEnricher.outputFile = outputFile
	}

	return jsonEnricher, nil
}

func (e *JsonEnricher) Close() error {
	return e.outputFile.Close()
}

func (e *JsonEnricher) Run(runErr chan<- error) {
	nodeName := e.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")
		runErr <- err

		return
	}

	e.logger.Info("Starting audit JSON logging on node " + nodeName)

	e.logLinesCache.OnEviction(
		func(ctx context.Context, reason ttlcache.EvictionReason, logItem *ttlcache.Item[int, *types.LogBucket]) {
			auditLogBucket := logItem.Value()

			e.logger.V(config.VerboseLevel).Info("Emit audit log for process",
				"pid", logItem.Key())
			e.dispatchSeccompLine(auditLogBucket, nodeName)
		})

	e.logger.Info(fmt.Sprintf("Setting up caches with expiry of %v", defaultCacheTimeout))

	clusterConfig, err := e.InClusterConfig()
	if err != nil {
		runErr <- fmt.Errorf("get in-cluster config: %w", err)
		return
	}

	e.clientset, err = e.NewForConfig(clusterConfig)
	if err != nil {
		runErr <- fmt.Errorf("load in-cluster config: %w", err)
		return
	}

	go e.containerIDCache.Start()
	go e.infoCache.Start()
	go e.logLinesCache.Start()
	go e.processCache.Start()

	// Use auditd logs as main source or syslog as fallback.
	filePath := common.LogFilePath()

	// If the file does not exist, then tail will wait for it to appear
	tailFile, err := e.TailFile(
		filePath,
		tail.Config{
			ReOpen: true,
			Follow: true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekEnd,
			},
		},
	)
	if err != nil {
		runErr <- fmt.Errorf("tailing file: %w", err)
		return
	}

	e.logger.Info("Reading from file " + filePath)

	timePrev := time.Now()

	for l := range e.Lines(tailFile) {
		if l.Err != nil {
			e.logger.Error(l.Err, "failed to tail")

			continue
		}

		timeNow := time.Now()
		if timePrev.Add(30 * time.Second).Before(timeNow) {
			e.logger.V(config.VerboseLevel).Info("Time to flush log lines")
			e.logLinesCache.DeleteExpired()

			timePrev = timeNow
		}

		line := l.Text
		e.logger.V(config.VerboseLevel).Info("Got line: " + line)

		if !IsAuditLine(line) {
			e.logger.V(config.VerboseLevel).Info("Not an audit line")

			continue
		}

		e.logger.V(config.VerboseLevel).Info("AuditLine Parsed: " + line)

		auditLine, err := ExtractAuditLine(line)
		if err != nil {
			e.logger.Error(err, "extract audit line")

			continue
		}

		if auditLine.AuditType != types.AuditTypeSeccomp {
			e.logger.V(config.VerboseLevel).Info("Only seccomp supported")

			continue
		}

		var logBucket *types.LogBucket
		if e.logLinesCache.Has(auditLine.ProcessID) {
			logBucket = e.logLinesCache.Get(auditLine.ProcessID).Value()
		} else {
			logBucket = &types.LogBucket{
				SyscallIds:    sync.Map{},
				ContainerInfo: nil,
				ProcessInfo:   nil,
				TimestampID:   auditLine.TimestampID,
			}
		}

		if logBucket.ContainerInfo == nil {
			logBucket.ContainerInfo = e.fetchContainerInfo(auditLine.ProcessID, nodeName)
		}

		if logBucket.ProcessInfo == nil {
			uid, gid, err := GetUidGid(line)
			if err != nil {
				e.logger.V(config.VerboseLevel).Info(
					"unable to get uid and gid", "line", line)
			}

			logBucket.ProcessInfo = e.fetchProcessInfo(auditLine.ProcessID,
				auditLine.Executable, uid, gid)
		}

		logBucket.SyscallIds.LoadOrStore(auditLine.SystemCallID, struct{}{})

		if !e.logLinesCache.Has(auditLine.ProcessID) {
			e.logLinesCache.Set(auditLine.ProcessID, logBucket, ttlcache.DefaultTTL)
		}
	}

	runErr <- fmt.Errorf("enricher failed: %w", e.Reason(tailFile))
	return
}

// Returns nil if the containerInfo couldn't be loaded.
func (e *JsonEnricher) fetchContainerInfo(processId int, nodeName string) *types.ContainerInfo {
	cID, errContainer := e.ContainerIDForPID(e.containerIDCache, processId)
	e.logger.V(config.VerboseLevel).Info(
		fmt.Sprintf("Container ID for Pid: %v with len %d", cID, len(cID)))

	var containerInfo *types.ContainerInfo

	if errContainer == nil && cID != "" {
		info, errGetContainerInfo := getContainerInfo(nodeName, cID, e.clientset, e.impl, e.infoCache, e.logger)
		if errGetContainerInfo == nil {
			containerInfo = info
		}
	} else {
		e.logger.V(config.VerboseLevel).Info("unable to get container Id", "err", errContainer)
	}

	e.logger.V(config.VerboseLevel).Info(
		fmt.Sprintf("Container Info: %v", containerInfo))

	return containerInfo
}

// Returns nil if the processInfo couldn't be loaded.
func (e *JsonEnricher) fetchProcessInfo(processId int, executable string, uid, gid uint32) *types.ProcessInfo {
	processInfo, err := GetProcessInfo(processId, executable, uid, gid, e.processCache, e.impl)
	e.logger.V(config.VerboseLevel).Info(
		fmt.Sprintf("Process Info: %v", processInfo))

	if err != nil {
		e.logger.V(config.VerboseLevel).Info("get process info", "err", err)
	}

	return processInfo
}

func (e *JsonEnricher) dispatchSeccompLine(
	logBucket *types.LogBucket, nodeName string,
) {
	var syscallNames []string

	logBucket.SyscallIds.Range(func(k, _ interface{}) bool {
		syscallId, errKey := k.(int32)
		if !errKey {
			return false
		}

		syscallName, err := syscallName(syscallId)
		if err != nil {
			e.logger.Error(
				err,
				"no syscall name found for ID", "syscallId", syscallId,
			)
		} else {
			syscallNames = append(syscallNames, syscallName)
		}

		return true
	})

	var resource map[string]string

	if logBucket.ProcessInfo == nil {
		e.logger.V(config.VerboseLevel).Info("process info not found")

		return
	}

	if logBucket.ContainerInfo == nil {
		e.logger.V(config.VerboseLevel).Info("Container info not found in cache")
	}

	if logBucket.ContainerInfo != nil {
		resource = map[string]string{
			"pod":       logBucket.ContainerInfo.PodName,
			"namespace": logBucket.ContainerInfo.Namespace,
			"container": logBucket.ContainerInfo.ContainerName,
		}
	}

	node := map[string]string{
		"name": nodeName,
	}

	isoTimestamp, err := common.AuditTimeToIso(logBucket.TimestampID)
	if err != nil {
		e.logger.Error(err, "unable to get audit timestamp")

		return
	}

	auditMap := map[string]interface{}{
		"version":    "spo/v1_alpha",
		"auditID":    uuid.New().String(),
		"executable": logBucket.ProcessInfo.Executable,
		"cmdLine":    logBucket.ProcessInfo.CmdLine,
		"uid":        logBucket.ProcessInfo.Uid,
		"gid":        logBucket.ProcessInfo.Gid,
		"resource":   resource,
		"pid":        logBucket.ProcessInfo.Pid,
		"node":       node,
		"syscalls":   syscallNames,
		"timestamp":  isoTimestamp,
	}

	auditJson, err := json.Marshal(auditMap)
	if err != nil {
		e.logger.Error(err, "unable to output audit line")

		return
	}

	auditLogOutputMutex.Lock()
	defer auditLogOutputMutex.Unlock()
	e.PrintJsonOutput(e.outputFile, string(auditJson))
}

func (e *JsonEnricher) ExitJsonEnricher(_ *cli.Context) {
	if e.outputFile == os.Stdout {
		if err := os.Stdout.Sync(); err != nil {
			e.logger.Error(err, "unable to sync stdout")
		}

		return
	}

	if err := e.outputFile.Close(); err != nil {
		e.logger.Error(err, "error closing output log file")
	}
}
