/*
Copyright The Kubernetes Authors.

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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"gopkg.in/natefinch/lumberjack.v2"

	apienricher "sigs.k8s.io/security-profiles-operator/api/grpc/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

const (
	// defaultAuditLogMaxBackups is the number of rotated audit log files kept
	// when neither a number nor an age is configured. Keeping them all would
	// fill the disk of the node.
	defaultAuditLogMaxBackups = 10

	// flushInterval is how often the expired log buckets are emitted while
	// lines arrive, in addition to the cache janitor.
	flushInterval = 30 * time.Second
)

// errTailEnded is reported when the audit log tail ends without an error.
var errTailEnded = errors.New("audit log tail ended")

type JsonEnricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	logger              logr.Logger
	containerIDCache    *ttlcache.Cache[string, string]
	containers          *containerInfos
	logLinesCache       *ttlcache.Cache[int, *types.LogBucket]
	processCache        *ttlcache.Cache[string, *types.ProcessInfo]
	logWriter           io.Writer
	enricherFilters     []types.EnricherFilterOptions
	bpfProcessCache     *bpfrecorder.BpfProcessCache
	auditLogOutputMutex sync.Mutex
	// nodeName is the node the enricher runs on, from the node name
	// environment variable.
	nodeName string
}

type JsonEnricherOptions struct {
	AuditFreq           time.Duration
	AuditLogPath        string
	AuditLogMaxSize     int
	AuditLogMaxAge      int
	AuditLogMaxBackups  int
	EnricherFiltersJson string
}

var JsonEnricherDefaultOptions = JsonEnricherOptions{
	AuditFreq:           time.Minute,
	AuditLogPath:        "",
	AuditLogMaxSize:     0,
	AuditLogMaxAge:      0,
	AuditLogMaxBackups:  0,
	EnricherFiltersJson: "[]",
}

func validate(opts JsonEnricherOptions) error {
	if opts.AuditFreq < 0 {
		return fmt.Errorf("invalid value for AuditFreq: %v", opts.AuditFreq)
	}

	if opts.AuditLogMaxBackups < 0 {
		return fmt.Errorf("invalid value for AuditLogMaxBackups: %v", opts.AuditLogMaxBackups)
	}

	if opts.AuditLogMaxSize < 0 {
		return fmt.Errorf("invalid value for AuditLogMaxSize: %v", opts.AuditLogMaxSize)
	}

	if opts.AuditLogMaxAge < 0 {
		return fmt.Errorf("invalid value for AuditLogMaxAge: %v", opts.AuditLogMaxAge)
	}

	return nil
}

func NewJsonEnricherArgs(logger logr.Logger, opts *JsonEnricherOptions) (*JsonEnricher, error) {
	actualOpts := JsonEnricherDefaultOptions

	if opts != nil {
		if err := validate(*opts); err != nil {
			return nil, err
		}

		if opts.AuditFreq != 0 {
			// If AuditFreq is set to zero default to 60 seconds
			actualOpts.AuditFreq = opts.AuditFreq
		}

		if opts.AuditLogPath != "" {
			actualOpts.AuditLogPath = opts.AuditLogPath
		}

		actualOpts.AuditLogMaxSize = opts.AuditLogMaxSize
		actualOpts.AuditLogMaxBackups = opts.AuditLogMaxBackups
		actualOpts.AuditLogMaxAge = opts.AuditLogMaxAge

		if opts.EnricherFiltersJson != "" {
			actualOpts.EnricherFiltersJson = opts.EnricherFiltersJson
		}
	}

	if actualOpts.AuditLogPath != "" && actualOpts.AuditLogMaxBackups == 0 &&
		actualOpts.AuditLogMaxAge == 0 {
		// lumberjack keeps every rotated file otherwise.
		actualOpts.AuditLogMaxBackups = defaultAuditLogMaxBackups
		logger.Info(
			"Neither a maximum number nor a maximum age of audit log backups is set, using a default",
			"maxBackups",
			defaultAuditLogMaxBackups,
		)
	}

	enricherFilters, err := GetEnricherFilters(actualOpts.EnricherFiltersJson, logger)
	if err != nil {
		return nil, fmt.Errorf("get enricher filters: %w", err)
	}

	logger.Info("Enricher Filters", "filters", enricherFilters)

	jsonEnricher := &JsonEnricher{
		impl:   newDefaultImpl(logger),
		logger: logger,
		containerIDCache: ttlcache.New(
			ttlcache.WithTTL[string, string](defaultCacheTimeout),
			ttlcache.WithCapacity[string, string](maxCacheItems),
		),
		containers: newContainerInfos(),
		logLinesCache: ttlcache.New(
			ttlcache.WithTTL[int, *types.LogBucket](actualOpts.AuditFreq),
			ttlcache.WithCapacity[int, *types.LogBucket](maxCacheItems),
			// Buckets are flushed on eviction. Touching them on every hit
			// would keep a busy process from ever emitting its records.
			ttlcache.WithDisableTouchOnHit[int, *types.LogBucket](),
		),
		processCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ProcessInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ProcessInfo](maxCacheItems),
		),
		enricherFilters: enricherFilters,
		bpfProcessCache: nil,
		// Read once, like the rest of the configuration.
		nodeName: os.Getenv(config.NodeNameEnvKey),
	}

	w, err := getWriter(actualOpts)
	if err != nil {
		return nil, err
	}

	jsonEnricher.logWriter = w

	return jsonEnricher, nil
}

func getWriter(opts JsonEnricherOptions) (io.Writer, error) {
	if opts.AuditLogPath == "" {
		return os.Stdout, nil // Ignore all other audit log file options
	}

	if err := ensureLogFile(opts); err != nil {
		return nil, fmt.Errorf("ensureLogFile: %w", err)
	}

	// lumberjack handles 0 size with default of 100 MB
	return &lumberjack.Logger{
		Filename:   opts.AuditLogPath,
		MaxSize:    opts.AuditLogMaxSize,
		MaxAge:     opts.AuditLogMaxAge,
		MaxBackups: opts.AuditLogMaxBackups,
		Compress:   false, // Future enhancement if required
	}, nil
}

// Run reads the audit log until ctx is done and sends the outcome to runErr:
// nil once it shut down, or the error which ended it. The records which are
// still buffered are emitted before it returns.
func (e *JsonEnricher) Run(ctx context.Context, runErr chan<- error) {
	runErr <- e.run(ctx)
}

func (e *JsonEnricher) run(ctx context.Context) error {
	nodeName := e.nodeName
	if nodeName == "" {
		err := fmt.Errorf("%s environment variable not set", config.NodeNameEnvKey)
		e.logger.Error(err, "unable to run enricher")

		return err
	}

	e.logger.Info("Starting audit JSON logging on node", "node", nodeName)

	unsubscribe := e.logLinesCache.OnEviction(
		func(ctx context.Context, reason ttlcache.EvictionReason, logItem *ttlcache.Item[int, *types.LogBucket]) {
			auditLogBucket := logItem.Value()
			if auditLogBucket == nil {
				return
			}

			// The eviction runs in its own goroutine, while the bucket may
			// still get lines.
			auditLogBucket.Mu.Lock()
			defer auditLogBucket.Mu.Unlock()

			auditLogBucket.Emitted = true

			// The pod may tell the container by now.
			if auditLogBucket.ContainerInfo == nil && auditLogBucket.ContainerID != "" {
				if info, err := e.containers.get(auditLogBucket.ContainerID); err == nil {
					auditLogBucket.ContainerInfo = info
				}
			}

			e.logger.V(config.VerboseLevel).Info("Emit audit log for process",
				"pid", logItem.Key())
			e.dispatchSeccompLine(auditLogBucket, nodeName)
		},
	)

	if err := e.containers.watch(ctx, e.impl, nodeName); err != nil {
		return err
	}

	e.logger.Info("Setting up caches", "expiry", defaultCacheTimeout)

	go e.containerIDCache.Start()
	defer e.containerIDCache.Stop()

	go e.containers.infoCache.Start()
	defer e.containers.infoCache.Stop()

	go e.logLinesCache.Start()
	defer e.logLinesCache.Stop()

	go e.processCache.Start()
	defer e.processCache.Stop()

	// Use auditd logs as main source or syslog as fallback.
	filePath := common.LogFilePath()

	// If the file does not exist, then the tailer waits for it to appear.
	tailFile, err := e.TailFile(filePath, tailer.Config{})
	if err != nil {
		return fmt.Errorf("tailing file: %w", err)
	}

	e.logger.Info("Reading from file", "path", filePath)

	bpfProcCache := bpfrecorder.NewBpfProcessCache(e.logger)

	//nolint:staticcheck,nolintlint // platform-dependent: always true on non-linux
	if err := bpfProcCache.Load(); err != nil {
		e.logger.Info("Unable to load BPF module. Using auditd", "error", err.Error())
	} else {
		e.bpfProcessCache = bpfProcCache

		defer bpfProcCache.Close()
	}

	defer func() {
		// Emit what the processes did since their buckets were last
		// flushed: deleting the buckets runs the eviction callbacks, and
		// unsubscribing waits for them before the writer gets closed.
		e.StopTail(tailFile)
		e.logLinesCache.DeleteAll()
		unsubscribe()
		e.closeLogWriter()
	}()

	timePrev := time.Now()
	lines := e.Lines(tailFile)

	for {
		select {
		case <-ctx.Done():
			e.logger.Info("Stopping audit JSON logging", "reason", ctx.Err().Error())

			return nil
		case line, ok := <-lines:
			if !ok {
				err := e.Reason(tailFile)
				if err == nil {
					err = errTailEnded
				}

				return fmt.Errorf("enricher failed: %w", err)
			}

			timeNow := time.Now()
			if timePrev.Add(flushInterval).Before(timeNow) {
				e.logger.V(config.VerboseLevel).Info("Time to flush log lines")
				e.logLinesCache.DeleteExpired()

				timePrev = timeNow
			}

			e.processLine(line)
		}
	}
}

// processLine adds a seccomp audit line to the log bucket of its process.
func (e *JsonEnricher) processLine(line string) {
	e.logger.V(config.VerboseLevel).Info("Got line", "line", line)

	// ExtractAuditLine rejects non-audit lines itself, so an IsAuditLine
	// call here would only repeat the same regex matching.
	auditLine, err := auditsource.ExtractAuditLine(line)
	if err != nil {
		e.logger.V(config.VerboseLevel).Info("Not an audit line")

		return
	}

	e.logger.V(config.VerboseLevel).Info("AuditLine parsed", "line", line)

	if auditLine.AuditType != types.AuditTypeSeccomp {
		e.logger.V(config.VerboseLevel).Info("Only seccomp supported")

		return
	}

	logBucket, cached := e.lockedLogBucket(auditLine)

	// Capture proc/pid/(cmdLine/environ) early; these files are ephemeral on some OS (e.g., Ubuntu).
	if logBucket.ProcessInfo == nil {
		// The uid and gid stay nil when the line carries none: defaulting to
		// the zero value would attribute the record to root.
		logBucket.ProcessInfo = e.fetchProcessInfo(auditLine.ProcessID,
			auditLine.Executable, auditLine.Uid, auditLine.Gid)
	}

	e.processEbpf(logBucket, auditLine)

	if logBucket.ContainerInfo == nil {
		logBucket.ContainerInfo, logBucket.ContainerID = e.fetchContainerInfo(
			auditLine.ProcessID,
		)
	}

	logBucket.SyscallIds.LoadOrStore(
		types.SyscallKey{ID: auditLine.SystemCallID, Arch: auditLine.Arch}, struct{}{},
	)

	logBucket.Mu.Unlock()

	if !cached {
		e.logLinesCache.Set(auditLine.ProcessID, logBucket, ttlcache.DefaultTTL)
	}
}

// closeLogWriter closes the audit log file. Stdout stays open for the logger.
func (e *JsonEnricher) closeLogWriter() {
	if e.logWriter == io.Writer(os.Stdout) {
		return
	}

	if closer, ok := e.logWriter.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			e.logger.Error(err, "unable to close log writer")
		}
	}
}

// lockedLogBucket returns the locked bucket of the process of the audit line,
// and whether it is cached already.
func (e *JsonEnricher) lockedLogBucket(
	auditLine *types.AuditLine,
) (logBucket *types.LogBucket, cached bool) {
	// A single Get: Has() followed by Get() can race with expiry or the
	// cache janitor, and Get() returns nil for an item that vanished in
	// between, which would panic in Value().
	if item := e.logLinesCache.Get(auditLine.ProcessID); item != nil {
		logBucket = item.Value()
	} else {
		// Get hides a bucket which expired but was not cleaned up yet, and
		// Set would overwrite it without an eviction, losing its records.
		// Deleting it emits it first.
		e.logLinesCache.Delete(auditLine.ProcessID)
	}

	if logBucket != nil {
		logBucket.Mu.Lock()

		switch {
		case logBucket.Emitted:
			// Emitted in the meantime, the line goes into a new one.
			logBucket.Mu.Unlock()
		case logBucket.ProcessInfo != nil && logBucket.ProcessInfo.Executable != auditLine.Executable:
			// Another executable runs with the PID now: the process
			// exec'd or the PID got reused. The bucket of the previous one
			// is emitted by the eviction of the deletion, the line starts a
			// new one.
			logBucket.Mu.Unlock()
			e.logLinesCache.Delete(auditLine.ProcessID)
		default:
			return logBucket, true
		}
	}

	logBucket = &types.LogBucket{
		SyscallIds:    sync.Map{},
		ContainerInfo: nil,
		ProcessInfo:   nil,
		TimestampID:   auditLine.TimestampID,
	}
	logBucket.Mu.Lock()

	return logBucket, false
}

func (e *JsonEnricher) processEbpf(logBucket *types.LogBucket, auditLine *types.AuditLine) {
	if e.bpfProcessCache != nil && logBucket.ProcessInfo != nil &&
		logBucket.ProcessInfo.CmdLine == "" {
		//nolint:staticcheck,nolintlint // platform-dependent
		cmdLine, errCmdLine := e.bpfProcessCache.GetCmdLine(auditLine.ProcessID)
		//nolint:staticcheck,nolintlint // platform-dependent
		if errCmdLine == nil {
			logBucket.ProcessInfo.CmdLine = cmdLine

			e.logger.V(config.VerboseLevel).Info("cmdline found in eBPF",
				"processId", auditLine.ProcessID, "cmdLine", cmdLine)
		} else {
			e.logger.V(config.VerboseLevel).Info("cmdline not found in eBPF also",
				"processId", auditLine.ProcessID)
		}
	}

	if e.bpfProcessCache != nil && logBucket.ProcessInfo != nil &&
		logBucket.ProcessInfo.ExecRequestId == nil {
		//nolint:staticcheck,nolintlint // platform-dependent
		procEnv, errEnv := e.bpfProcessCache.GetEnv(auditLine.ProcessID)
		//nolint:staticcheck,nolintlint // platform-dependent
		if errEnv == nil {
			reqId, ok := procEnv[requestIdEnv]
			if !ok {
				e.logger.V(config.VerboseLevel).Info("exec request id info not found in eBPF also",
					"processId", auditLine.ProcessID)
			} else {
				logBucket.ProcessInfo.ExecRequestId = &reqId

				e.logger.V(config.VerboseLevel).
					Info("exec request id info found in eBPF", "reqId", reqId,
						"processId", auditLine.ProcessID)
			}
		} else {
			e.logger.V(config.VerboseLevel).Error(errEnv, "fetching exec request id",
				"processId", auditLine.ProcessID)
		}
	}
}

// fetchContainerInfo returns the info of the container of a process, or nil if
// it is not known. The ID of a container which its pod does not tell yet is
// returned as well, the next line of the process or the emission of its bucket
// look it up again. Waiting for it here would stall the processing of the
// lines.
func (e *JsonEnricher) fetchContainerInfo(
	processId int,
) (info *types.ContainerInfo, containerID string) {
	cID, errContainer := e.ContainerIDForPID(e.containerIDCache, processId)
	e.logger.V(config.VerboseLevel).Info("Container ID for PID",
		"containerID", cID, "len", len(cID))

	if errContainer != nil || cID == "" {
		e.logger.V(config.VerboseLevel).Info("unable to get container Id", "error", errContainer)

		return nil, ""
	}

	containerInfo, err := e.containers.get(cID)
	if err != nil {
		e.logger.V(config.VerboseLevel).Info("Container info not known yet",
			"containerID", cID, "reason", err.Error())

		return nil, cID
	}

	e.logger.V(config.VerboseLevel).Info("Container info",
		"containerInfo", containerInfo)

	return containerInfo, cID
}

// Returns nil if the processInfo couldn't be loaded.
func (e *JsonEnricher) fetchProcessInfo(
	processId int,
	executable string,
	uid, gid *uint32,
) *types.ProcessInfo {
	processInfo, err := GetProcessInfo(processId, executable, uid, gid, e.processCache, e.impl)
	e.logger.V(config.VerboseLevel).Info("Process info",
		"processInfo", processInfo)

	if err != nil {
		e.logger.V(config.VerboseLevel).Info("get process info", "error", err)
	}

	return processInfo
}

func (e *JsonEnricher) dispatchSeccompLine(
	logBucket *types.LogBucket, nodeName string,
) {
	var syscallNames []string

	logBucket.SyscallIds.Range(func(k, _ any) bool {
		syscall, ok := k.(types.SyscallKey)
		if !ok {
			return false
		}

		syscallName, err := syscallName(syscall.ID, syscall.Arch)
		if err != nil {
			e.logger.Error(
				err,
				"no syscall name found for ID", "syscallId", syscall.ID, "arch", syscall.Arch,
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

	// As close as possible to k8s server side audit json
	// In future map this to a object and produce JSON using marshal/unmarshal functions
	auditMap := map[string]any{
		"version":    "spo/v1_alpha",
		"auditID":    uuid.New().String(),
		"executable": logBucket.ProcessInfo.Executable,
		"cmdLine":    logBucket.ProcessInfo.CmdLine,
		"resource":   resource,
		"pid":        logBucket.ProcessInfo.Pid,
		"node":       node,
		"syscalls":   syscallNames,
		"timestamp":  isoTimestamp,
	}

	// Set only when the audit line carried them. They must not default to 0,
	// which would attribute the record to root, and emitting null instead would
	// break any consumer parsing them as integers.
	if logBucket.ProcessInfo.Uid != nil {
		auditMap["uid"] = *logBucket.ProcessInfo.Uid
	}

	if logBucket.ProcessInfo.Gid != nil {
		auditMap["gid"] = *logBucket.ProcessInfo.Gid
	}

	if logBucket.ProcessInfo.ExecRequestId != nil {
		auditMap["requestUID"] = *logBucket.ProcessInfo.ExecRequestId
	}

	logLevel := ApplyEnricherFilters(auditMap, e.enricherFilters)
	if logLevel == types.EnricherLogLevelNone {
		e.logger.V(config.VerboseLevel).Info("Skip logging", "auditMap", auditMap)

		return
	}

	auditJson, err := json.Marshal(auditMap)
	if err != nil {
		e.logger.Error(err, "unable to output audit line")

		return
	}

	e.auditLogOutputMutex.Lock()
	defer e.auditLogOutputMutex.Unlock()

	e.PrintJsonOutput(e.logWriter, auditJson)
}

func ensureLogFile(opts JsonEnricherOptions) error {
	if err := os.MkdirAll(filepath.Dir(opts.AuditLogPath), 0o700); err != nil {
		return err
	}

	return nil
}
