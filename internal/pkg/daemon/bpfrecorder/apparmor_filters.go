//go:build linux && !no_bpf
// +build linux,!no_bpf

/*
Copyright 2021 The Kubernetes Authors.

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
	"/etc/locale.alias/",
	"/etc/localtime",
	"/usr/share/locale/",
	"/usr/lib/locale/",
	"/etc/locale.alias",
}

// List of known paths for commonly written to files.
var knownWritePrefixes = []string{
	"/dev/log",
}

// excludedFilePrefixes of known file paths which should be filter out
// from the apparmor profile.
var excludedFilePrefixes = []string{
	"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
	"/usr/bin/runc",
}
