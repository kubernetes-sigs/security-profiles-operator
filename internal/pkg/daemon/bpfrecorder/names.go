//go:build linux && !no_bpf

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

package bpfrecorder

import "slices"

// Names of the maps and global variables of recorder.bpf.c the recorder uses.
// Every name has to be listed in bpfMapNames or bpfGlobalNames, a test checks
// them against the compiled objects.
const (
	mapIsRecording         = "is_recording"
	mapEvents              = "events"
	mapExcludeMntns        = "exclude_mntns"
	mapRecordedSyscalls    = "recorded_syscalls"
	mapActivePids          = "active_pids"
	mapChildPids           = "child_pids"
	mapExcludeKeys         = "exclude_keys"
	mapSeccompInitialized  = "seccomp_initialized"
	mapApparmorInitialized = "apparmor_initialized"
	mapLostEvents          = "lost_events"
	mapRecordedCaps        = "recorded_caps"
	mapRecordedSockets     = "recorded_sockets"
	mapLastFileEvent       = "last_file_event"
	globalFilterName       = "filter_name"
	globalUseCgroupID      = "use_cgroup_id"
	globalUseMntnsSeq      = "use_mntns_seq"
	globalCaptureExecArgs  = "capture_exec_args"
	globalInitComms        = "init_comms"
	globalInitExePrefix    = "init_exe_prefix"
	progSysEnterExecve     = "sys_enter_execve"
	progSysEnterExecveat   = "sys_enter_execveat"
	progSysEnterGetgid     = "sys_enter_getgid"
	progSysEnter           = "sys_enter"
	progSchedProcessExec   = "sched_process_exec"
	progSchedProcessExit   = "sched_process_exit"
	progSchedProcessFork   = "sched_process_fork"
	progFileOpen           = "file_open"
	progFileLock           = "file_lock"
	progMmapFile           = "mmap_file"
	progPathMkdir          = "path_mkdir"
	progPathMknod          = "path_mknod"
	progPathUnlink         = "path_unlink"
	progPathRmdir          = "path_rmdir"
	progPathRename         = "path_rename"
	progPathLink           = "path_link"
	progPathSymlink        = "path_symlink"
	progPathTruncate       = "path_truncate"
	progPathChmod          = "path_chmod"
	progPathChown          = "path_chown"
	progInodeGetattr       = "inode_getattr"
	progFileMprotect       = "file_mprotect"
	progBprmCheckSecurity  = "bprm_check_security"
	progSysEnterSocket     = "sys_enter_socket"
	progCapCapable         = "cap_capable"
)

var (
	bpfMapNames = []string{
		mapIsRecording, mapEvents, mapExcludeMntns, mapRecordedSyscalls,
		mapActivePids, mapChildPids, mapExcludeKeys, mapSeccompInitialized,
		mapApparmorInitialized, mapLostEvents, mapRecordedCaps, mapRecordedSockets,
		mapLastFileEvent,
	}

	bpfGlobalNames = []string{
		globalFilterName, globalUseCgroupID, globalUseMntnsSeq, globalCaptureExecArgs,
		globalInitComms, globalInitExePrefix,
	}

	// baseHooks are attached by the recorder in any case.
	baseHooks = []string{
		progSysEnter,
		progSysEnterGetgid,
		progSchedProcessExit,
	}

	// filterHooks track the children of the recorded program, they are
	// attached by the recorder with a program name filter only.
	filterHooks = []string{
		progSchedProcessFork,
		progSchedProcessExec,
	}

	// execHooks send the arguments of the execs, which only the process cache
	// needs, see capture_exec_args.
	execHooks = []string{
		progSysEnterExecve,
		progSysEnterExecveat,
	}

	// appArmorHooks are attached when recording AppArmor profiles.
	appArmorHooks = []string{
		progFileOpen,
		progFileLock,
		progMmapFile,
		progPathMkdir,
		progPathMknod,
		progPathUnlink,
		progPathRmdir,
		progPathRename,
		progPathLink,
		progPathSymlink,
		progPathTruncate,
		progPathChmod,
		progPathChown,
		progInodeGetattr,
		progFileMprotect,
		progBprmCheckSecurity,
		progSysEnterSocket,
		progCapCapable,
	}

	// procCacheHooks are attached by the process cache.
	procCacheHooks = append(slices.Clone(execHooks), progSysEnterGetgid)

	// procCacheUnusedMaps are the maps of the recorder which the hooks of the
	// process cache do not fill, see BpfProcessCache.Load.
	procCacheUnusedMaps = []string{
		mapExcludeMntns, mapRecordedSyscalls, mapActivePids, mapChildPids,
		mapExcludeKeys, mapSeccompInitialized, mapApparmorInitialized,
		mapRecordedCaps, mapRecordedSockets, mapLastFileEvent,
	}
)
