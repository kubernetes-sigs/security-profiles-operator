//go:build s390x && linux
// +build s390x,linux

/*
Copyright 2024 The Kubernetes Authors.

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

import (
	"strings"
	"syscall"
)

// UnameMachineToString converts uname.Machine to a string for s390x/ppc64le.
func UnameMachineToString(uname *syscall.Utsname) string {
	return toStringUint8Z(uname.Machine)
}

// UnameReleaseToString converts uname.Release to a string for s390x/ppc64le.
func UnameReleaseToString(uname *syscall.Utsname) string {
	return toStringUint8Z(uname.Release)
}

// Helper function to convert [65]uint8 to string.
func toStringUint8Z(array [65]uint8) string {
	n := 0
	for i, v := range array {
		if v == 0 {
			n = i
			break
		}
	}
	return string(array[:n])
}
