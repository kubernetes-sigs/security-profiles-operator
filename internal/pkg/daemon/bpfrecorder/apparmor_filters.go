//go:build linux && !no_bpf
// +build linux,!no_bpf

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
	"/etc/locale/",
	"/etc/locale.alias/",
	"/etc/localtime",
	"/usr/share/locale/",
}

// List of known paths for commonly written to files.
var knownWritePrefixes = []string{
	"/dev/log",
}
