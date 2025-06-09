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
	RequestUserIdEnv   = "REQUEST_USER_ID"
	RequestUserNameEnv = "REQUEST_USER_NAME"
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

	if err := populateProcessCache(pid, executable, uid, gid, processCache, impl); err != nil {
		errDetailsFetch = fmt.Errorf("get process info for pid: %w", err)
	}

	item = processCache.Get(pid)
	if item != nil {
		return item.Value(), errDetailsFetch
	}

	return nil, errors.New("no process info for Pid")
}

func populateProcessCache(
	pid int, executable string, uid, gid uint32,
	processCache *ttlcache.Cache[int, *types.ProcessInfo],
	impl impl,
) error {
	procInfo := types.ProcessInfo{
		Pid:        pid,
		Executable: executable,
		Uid:        uid,
		Gid:        gid,
	}
	processCache.Set(pid, &procInfo, ttlcache.DefaultTTL)

	cmdLine, cerr := impl.CmdlineForPID(pid)
	if cerr != nil {
		return cerr
	}

	env, envErr := impl.EnvForPid(pid)
	if envErr != nil {
		return envErr
	}

	reqUserId, ok := env[RequestUserIdEnv]
	if ok {
		procInfo.RequestUserId = &reqUserId
	}

	reqUserName, ok := env[RequestUserNameEnv]
	if ok {
		procInfo.RequestUserName = &reqUserName
	}

	procInfo.CmdLine = cmdLine

	return nil
}
