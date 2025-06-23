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
	"errors"
	"fmt"
	"strings"

	"github.com/jellydator/ttlcache/v3"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

var (

	// ErrProcessNotFound is the error returned by ContainerIDForPID if the
	// process path could not be found in /proc.
	ErrProcessNotFound = errors.New("process not found in process file system path")

	// ErrCmdlineNotFound is the error returned by ContainerIDForPID if the
	// process path could not be found in /proc.
	ErrCmdlineNotFound = errors.New("cmdline empty or not found for the process")
)

const (
	requestIdEnv = "SPO_EXEC_REQUEST_UID"
)

func GetProcessInfo(
	pid int, executable string, uid, gid uint32,
	processCache *ttlcache.Cache[int, *types.ProcessInfo],
	impl impl,
) (*types.ProcessInfo, error) {
	// Check the cache first
	item := processCache.Get(pid)
	if item != nil {
		return item.Value(), nil
	}

	var errDetailsFetch error

	if procErrors := populateProcessCache(pid, executable, uid, gid, processCache, impl); len(procErrors) > 0 {
		errDetailsFetch = fmt.Errorf("get process info for pid: %w", errors.Join(procErrors...))
	}

	item = processCache.Get(pid)
	if item != nil {
		return item.Value(), errDetailsFetch
	}

	return nil, errors.New("no process info for Pid")
}

func extractSPORequestUID(input string) (string, bool) {
	prefix := "SPO_EXEC_REQUEST_UID="

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

	return input[dataStart:absEnd], true
}

func populateProcessCache(
	pid int, executable string, uid, gid uint32,
	processCache *ttlcache.Cache[int, *types.ProcessInfo],
	impl impl,
) []error {
	var errs []error

	procInfo := types.ProcessInfo{
		Pid:        pid,
		Executable: executable,
		Uid:        uid,
		Gid:        gid,
	}

	cmdLineFound := false

	cmdLine, err := impl.CmdlineForPID(pid)
	if err == nil {
		procInfo.CmdLine = cmdLine
		cmdLineFound = true
	} else {
		errs = append(errs, fmt.Errorf("failed to get cmdline for pid %d: %w", pid, err))
	}

	reqIdEnvFound := false

	env, err := impl.EnvForPid(pid)
	if err == nil {
		reqId, ok := env[requestIdEnv]
		if ok {
			procInfo.ExecRequestId = &reqId
			reqIdEnvFound = true
		}
	} else {
		errs = append(errs, fmt.Errorf("failed to get env for pid %d: %w", pid, err))
	}

	if !reqIdEnvFound && cmdLineFound {
		// If the env does not contain and cmdLine is valid,
		// search for it, Example cmdLine: env SPO_EXEC_REQUEST_UID=dbbf5fca-c955-4922-99d2-27a50212071c ls
		reqId, ok := extractSPORequestUID(cmdLine)
		if ok {
			procInfo.ExecRequestId = &reqId
		}
	}

	// After calling set don't alter any field in procInfo
	processCache.Set(pid, &procInfo, ttlcache.DefaultTTL)

	return errs
}
