//go:build linux && !no_bpf && !ppc64le && !s390x
// +build linux,!no_bpf,!ppc64le,!s390x

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

package util

import (
	"strings"
	"syscall"
)

// unameMachineToString converts uname.Machine to a string for amd64.
func unameMachineToString(uname *syscall.Utsname) string {
	return toStringInt8(uname.Machine)
}

// unameReleaseToString converts uname.Release to a string for amd64.
func unameReleaseToString(uname *syscall.Utsname) string {
	return toStringInt8(uname.Release)
}

func toStringInt8(array [65]int8) string {
	var buf [65]byte
	for i, b := range array {
		buf[i] = byte(b)
	}

	return toStringByte(buf[:])
}

func toStringByte(array []byte) string {
	str := string(array)
	if i := strings.Index(str, "\x00"); i != -1 {
		str = str[:i]
	}

	return str
}
