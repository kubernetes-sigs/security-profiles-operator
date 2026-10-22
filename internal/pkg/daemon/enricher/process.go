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
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// ErrProcessNotFound is the error returned by CmdlineForPID and
// ExecRequestIDForPID if the files of the process could not be read from
// /proc.
var ErrProcessNotFound = errors.New("process not found in process file system path")

const requestIdEnv = config.ExecRequestUIDEnvKey

// GetProcessInfo returns the details of the process with the PID. The
// executable, uid and gid come from the audit line, the rest from the process.
// The returned info is the caller's own, it is never shared with the cache.
//
// The cache is keyed by PID and process start time, so that a process reusing
// the PID of a cached one does not get its command line and exec request. The
// last process seen with a PID is cached under the PID alone as well: audit
// lines are read with a delay, and the lines of a process which exited in
// between belong to it. startedLater, if not nil, reports whether the process
// which started the duration after the boot started after the audit line got
// logged: then it reused the PID of the process of the line.
func GetProcessInfo(
	pid int, executable string, uid, gid *uint32,
	processCache *ttlcache.Cache[string, *types.ProcessInfo],
	impl impl,
	startedLater func(started time.Duration) bool,
) (*types.ProcessInfo, error) {
	withLine := func(cached *types.ProcessInfo) *types.ProcessInfo {
		info := *cached
		info.Executable = executable
		info.Uid = uid
		info.Gid = gid

		return &info
	}

	lastKey := strconv.Itoa(pid)

	startTime, err := impl.ProcessStartTime(pid)
	if err != nil {
		if item := processCache.Get(lastKey); item != nil {
			return withLine(item.Value()), nil
		}

		// The details of a process which is gone cannot be read either.
		info := &types.ProcessInfo{Pid: pid}
		if !errors.Is(err, fs.ErrNotExist) {
			info, _ = processInfo(pid, impl)
		}

		return withLine(info), fmt.Errorf("get process start time for pid %d: %w", pid, err)
	}

	cacheKey := lastKey + "_" + strconv.FormatInt(int64(startTime), 10)

	if startedLater != nil && startedLater(startTime) {
		// The details of the running process are not the ones of the line.
		// The last process seen with the PID is the one of the line, unless
		// it is the running one.
		if last := processCache.Get(lastKey); last != nil {
			if running := processCache.Get(cacheKey); running == nil ||
				running.Value() != last.Value() {
				return withLine(last.Value()), nil
			}
		}

		return withLine(&types.ProcessInfo{Pid: pid}),
			fmt.Errorf("%w: pid %d", errProcessStartedLater, pid)
	}

	if item := processCache.Get(cacheKey); item != nil {
		return withLine(item.Value()), nil
	}

	info, errs := processInfo(pid, impl)
	processCache.Set(cacheKey, info, ttlcache.DefaultTTL)
	processCache.Set(lastKey, info, ttlcache.DefaultTTL)

	if len(errs) > 0 {
		return withLine(info), fmt.Errorf("get process info for pid: %w", errors.Join(errs...))
	}

	return withLine(info), nil
}

// processInfo reads the details of the process with the PID which do not come
// from the audit line.
func processInfo(pid int, impl impl) (*types.ProcessInfo, []error) {
	var errs []error

	procInfo := types.ProcessInfo{
		Pid: pid,
	}

	cmdLineFound := false

	cmdLine, err := impl.CmdlineForPID(pid)
	if err == nil {
		procInfo.CmdLine = cmdLine
		cmdLineFound = true
	} else {
		errs = append(errs, fmt.Errorf("failed to get cmdline for pid %d: %w", pid, err))
	}

	// Only the processes of kubectl exec carry a request ID, so a missing
	// one is no error, which would hide the real failures of reading the
	// details of a process.
	reqIdEnvFound := false

	reqId, ok, err := impl.ExecRequestIDForPID(pid)
	if err == nil {
		if ok {
			procInfo.ExecRequestId = &reqId
			reqIdEnvFound = true
		}
	} else {
		errs = append(errs, fmt.Errorf("failed to get env for pid %d: %w", pid, err))
	}

	// Special case: Extract UID directly from cmdLine if 'env' variable is missing it.
	// e.g., "env SPO_EXEC_REQUEST_UID=dbbf5fca-c955-4922-99d2-27a50212071c ls"
	if !reqIdEnvFound && cmdLineFound {
		if reqId, ok := extractSPORequestUID(cmdLine); ok {
			procInfo.ExecRequestId = &reqId
		}
	}

	return &procInfo, errs
}

func extractSPORequestUID(input string) (string, bool) {
	prefix := requestIdEnv + "="

	start := strings.Index(input, prefix)
	if start == -1 {
		return "", false
	}

	dataStart := start + len(prefix)

	if dataStart >= len(input) {
		return "", false
	}

	end := strings.IndexAny(input[dataStart:], " \t\n\r")

	if end == -1 {
		return input[dataStart:], true
	}

	absEnd := dataStart + end

	if absEnd == dataStart {
		return "", false
	}

	return input[dataStart:absEnd], true
}
