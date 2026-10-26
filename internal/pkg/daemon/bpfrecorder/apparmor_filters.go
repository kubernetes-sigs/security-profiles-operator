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

// List of known paths containing systems libraries.
// Taken from /etc/apparmor.d/abstractions/base.
var knownLibrariesPrefixes = []string{
	"/usr/lib32/locale/",
	"/usr/lib64/locale/",
	"/usr/lib32/gconv/",
	"/usr/lib64/gconv/",
	"/usr/lib/x86_64-linux-gnu/",
	"/lib/x86_64-linux-gnu/",
	"/usr/lib/aarch64-linux-gnu/",
	"/lib/aarch64-linux-gnu/",
	"/lib64/",
	"/lib/tls/",
	"/usr/lib/tls/",
}

// List of known paths for commonly read from files.
// Taken from /etc/apparmor.d/abstractions/base.
var knownReadPrefixes = []string{
	"/dev/random",
	"/dev/urandom",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d/",
	"/etc/locale/",
	"/etc/localtime",
	"/usr/share/locale/",
	"/usr/lib/locale/",
	"/etc/locale.alias",
}

// List of known paths for commonly written to files.
var knownWritePrefixes = []string{
	"/dev/log",
}

// noGlobPrefixes are the directories whose files never get allowed with a
// glob, see allowAnyFiles. Their files are devices and kernel interfaces, like
// /dev/mem or /proc/@{pid}/mem, which two unrelated files of the same
// directory must not allow. The file systems of shared memory and message
// queues below /dev are excepted, see globPrefixes.
var noGlobPrefixes = []string{
	"/dev/",
	"/proc/",
	"/sys/",
}

// globPrefixes are the directories below noGlobPrefixes whose files do get
// allowed with a glob. They hold files with random names, like the psm_*
// shared memory of Python multiprocessing or the .org.chromium.* files of
// Chromium, which a recording cannot capture up front.
var globPrefixes = []string{
	"/dev/mqueue/",
	"/dev/shm/",
}

// noGlob reports whether the file never gets allowed with a glob, see
// noGlobPrefixes.
func noGlob(path string) bool {
	return isKnownFile(path, noGlobPrefixes) && !isKnownFile(path, globPrefixes)
}

// excludedFilePrefixes of known file paths which should be filter out
// from the apparmor profile.
var excludedFilePrefixes = []string{
	"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
	"/usr/bin/runc",
}
