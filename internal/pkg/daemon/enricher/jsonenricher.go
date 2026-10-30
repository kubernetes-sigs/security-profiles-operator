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
	"slices"
	"sync"
	"time"
	"uuid"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"gopkg.in/natefinch/lumberjack.v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/auditsource"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/tailer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// defaultAuditLogMaxBackups is the number of rotated audit log files kept
	// when neither a number nor an age is configured. Keeping them all would
	// fill the disk of the node.
	defaultAuditLogMaxBackups = 10

	// maxProcessInfoItems bounds the process cache. Every process takes two
	// entries, one by PID and start time and one by PID for the processes
	// which exited before their lines got read, so it holds as many
	// processes as the other caches hold entries.
	maxProcessInfoItems = 2 * maxCacheItems

	// noContainerRecheck is how long the lines of a process which runs
	// outside of a container do not look its container up again.
	noContainerRecheck = time.Second
)

// errTailEnded is reported when the audit log tail ends without an error.
var errTailEnded = errors.New("audit log tail ended")

// bpfProcesses tells the command line, the arguments and the request UID of
// the environment of the processes which the BPF process cache saw executing.
type bpfProcesses interface {
	GetCmdLineAndRequestUID(pid int) (cmdLine string, args []string, requestUID string, err error)
}

type JsonEnricher struct {
	impl
	logger          logr.Logger
	lookup          *containerLookup
	logLinesCache   *ttlcache.Cache[int, *types.LogBucket]
	processCache    *ttlcache.Cache[string, *types.ProcessInfo]
	logWriter       io.Writer
	enricherFilters []types.EnricherFilterOptions
	// bpfProcessCache is nil if the BPF process cache cannot be loaded.
	bpfProcessCache     bpfProcesses
	auditLogOutputMutex sync.Mutex
	// nodeName is the node the enricher runs on, from the node name
	// environment variable.
	nodeName string
	// warned holds the warnings about unknown syscalls which got logged
	// already, which would otherwise be logged for every audit line.
	warned onceWarner
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
		lookup: newContainerLookup(logger),
		logLinesCache: ttlcache.New(
			ttlcache.WithTTL[int, *types.LogBucket](actualOpts.AuditFreq),
			ttlcache.WithCapacity[int, *types.LogBucket](maxCacheItems),
			// Buckets are flushed on eviction. Touching them on every hit
			// would keep a busy process from ever emitting its records.
			ttlcache.WithDisableTouchOnHit[int, *types.LogBucket](),
		),
		processCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ProcessInfo](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *types.ProcessInfo](maxProcessInfoItems),
		),
		enricherFilters: enricherFilters,
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
	if err := checkNodeName(e.logger, nodeName); err != nil {
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

			// The BPF event of the exec of the process may have got processed
			// by now, and the pod may tell the container.
			e.processEbpf(auditLogBucket, logItem.Key())

			if auditLogBucket.ContainerInfo == nil && auditLogBucket.ContainerID != "" {
				if info, err := e.lookup.containers.get(auditLogBucket.ContainerID); err == nil {
					auditLogBucket.ContainerInfo = info
				}
			}

			e.logger.V(config.VerboseLevel).Info("Emit audit log for process",
				"pid", logItem.Key())
			e.dispatchSeccompLine(auditLogBucket, nodeName)
		},
	)

	stopLookup, err := e.lookup.start(ctx, e.impl, nodeName)
	if err != nil {
		return err
	}
	defer stopLookup()

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

	// The janitor of the cache emits the buckets once they expire.
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

			e.processLine(line)
		}
	}
}

// processLine adds a seccomp audit line to the log bucket of its process.
func (e *JsonEnricher) processLine(line string) {
	e.logger.V(config.VerboseLevel).Info("Got line", "line", line)

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
			auditLine.Executable, auditLine.Uid, auditLine.Gid, auditTime(auditLine))
	}

	e.processEbpf(logBucket, auditLine.ProcessID)

	if logBucket.ContainerInfo == nil && time.Since(logBucket.NoContainerAt) >= noContainerRecheck {
		var noContainer bool

		logBucket.ContainerInfo, logBucket.ContainerID, noContainer = e.fetchContainerInfo(
			auditLine.ProcessID,
			auditTime(auditLine),
		)

		logBucket.NoContainerAt = time.Time{}
		if noContainer {
			logBucket.NoContainerAt = time.Now()
		}
	}

	logBucket.SyscallIds[types.SyscallKey{ID: auditLine.SystemCallID, Arch: auditLine.Arch}] = struct{}{}

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
		SyscallIds:    map[types.SyscallKey]struct{}{},
		ContainerInfo: nil,
		ProcessInfo:   nil,
		TimestampID:   auditLine.TimestampID,
	}
	logBucket.Mu.Lock()

	return logBucket, false
}

// processEbpf fills in what the process file system did not tell about the
// process with the PID from the BPF process cache. It is looked up until it is
// found, once per line of the bucket and when the bucket gets emitted: the
// audit line of a process which exited right away can be read before the BPF
// event of its exec got processed. Once found, a process which did not get it
// from its exec does not get it later on.
func (e *JsonEnricher) processEbpf(logBucket *types.LogBucket, pid int) {
	if e.bpfProcessCache == nil || logBucket.ProcessInfo == nil || logBucket.BpfFound {
		return
	}

	needCmdLine := logBucket.ProcessInfo.CmdLine == ""
	needRequest := logBucket.ProcessInfo.ExecRequestId == nil

	if !needCmdLine && !needRequest {
		return
	}

	// A single lookup, which checks the process with the PID only once.
	//nolint:staticcheck,nolintlint // platform-dependent
	cmdLine, args, envRequestUID, err := e.bpfProcessCache.GetCmdLineAndRequestUID(pid)
	//nolint:staticcheck,nolintlint // platform-dependent
	if err != nil {
		e.logger.V(config.VerboseLevel).Info("process not found in eBPF either",
			"processId", pid, "error", err.Error())

		return
	}

	logBucket.BpfFound = true

	if needCmdLine {
		logBucket.ProcessInfo.CmdLine = cmdLine

		e.logger.V(config.VerboseLevel).Info("cmdline found in eBPF",
			"processId", pid, "cmdLine", cmdLine)
	}

	if needRequest {
		reqId, ok := execRequestUID(args, func() (string, bool) {
			return envRequestUID, envRequestUID != ""
		})
		if !ok {
			e.logger.V(config.VerboseLevel).Info("exec request id info not found in eBPF either",
				"processId", pid)

			return
		}

		logBucket.ProcessInfo.ExecRequestId = &reqId

		e.logger.V(config.VerboseLevel).
			Info("exec request id info found in eBPF", "reqId", reqId,
				"processId", pid)
	}
}

// fetchContainerInfo returns the info of the container of a process, or nil if
// it is not known. The ID of a container which its pod does not tell yet is
// returned as well, the next line of the process or the emission of its bucket
// look it up again. Waiting for it here would stall the processing of the
// lines. A process which exited gets the container it was last seen running
// in. eventTime is when the line of the process got logged. noContainer is
// true if the process runs outside of a container, or exited without a known
// container, which looking it up again does not change.
func (e *JsonEnricher) fetchContainerInfo(
	processId int, eventTime time.Time,
) (info *types.ContainerInfo, containerID string, noContainer bool) {
	cID, errContainer := e.lookup.containerIDForProcess(e.impl, processId, eventTime)
	e.logger.V(config.VerboseLevel).Info("Container ID for PID",
		"containerID", cID, "len", len(cID))

	if errContainer != nil || cID == "" {
		e.logger.V(config.VerboseLevel).Info("unable to get container Id", "error", errContainer)

		return nil, "", errors.Is(errContainer, util.ErrContainerIDNotFound) ||
			processGone(errContainer)
	}

	containerInfo, err := e.lookup.containers.get(cID)
	if err != nil {
		e.logger.V(config.VerboseLevel).Info("Container info not known yet",
			"containerID", cID, "reason", err.Error())

		return nil, cID, false
	}

	e.logger.V(config.VerboseLevel).Info("Container info",
		"containerInfo", containerInfo)

	return containerInfo, cID, false
}

// fetchProcessInfo returns the details of the process which logged an audit
// line at eventTime. What could not be read stays empty, see GetProcessInfo.
func (e *JsonEnricher) fetchProcessInfo(
	processId int,
	executable string,
	uid, gid *uint32,
	eventTime time.Time,
) *types.ProcessInfo {
	startedLater := func(started time.Duration) bool {
		return errors.Is(e.lookup.startedBefore(e.impl, processId, started, eventTime),
			errProcessStartedLater)
	}

	processInfo, err := GetProcessInfo(
		processId, executable, uid, gid, e.processCache, e.impl, startedLater,
	)
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
	// processLine fills in the process info of every bucket before it gets
	// cached, a bucket without one is not emitted in any case.
	if logBucket.ProcessInfo == nil {
		e.logger.V(config.VerboseLevel).Info("process info not found")

		return
	}

	// The names are sorted, so that buckets with the same syscalls emit the
	// same record, and never null, which consumers expecting a list would
	// trip over.
	syscallNames := make([]string, 0, len(logBucket.SyscallIds))

	for syscall := range logBucket.SyscallIds {
		syscallName, err := syscallName(syscall.ID, syscall.Arch)
		if err != nil {
			e.warned.warn(
				e.logger, unknownSyscallKey(syscall.Arch),
				"no syscall name found for ID",
				"syscallId", syscall.ID,
				"arch", syscall.Arch,
				"error", err.Error(),
			)

			continue
		}

		syscallNames = append(syscallNames, syscallName)
	}

	slices.Sort(syscallNames)
	syscallNames = slices.Compact(syscallNames)

	// The nested maps hold any values, which the filters walk into for keys
	// like resource/pod, see matchPathFilterLabel.
	var resource map[string]any

	if logBucket.ContainerInfo == nil {
		e.logger.V(config.VerboseLevel).Info("Container info not found in cache")
	} else {
		resource = map[string]any{
			"pod":       logBucket.ContainerInfo.PodName,
			"namespace": logBucket.ContainerInfo.Namespace,
			"container": logBucket.ContainerInfo.ContainerName,
		}
	}

	node := map[string]any{
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
		"auditID":    uuid.NewV4().String(),
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
