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

import bpf "github.com/aquasecurity/libbpfgo"

type BpfRecorderSeccomp struct {
}

func (*BpfRecorderSeccomp) AddSpecificInstrumentation(_ *BpfRecorder, _ *bpf.Module) error {
	return nil
}

func (*BpfRecorderSeccomp) SetupAndProcessSpecificEvents(_ *BpfRecorder, _ *bpf.Module) error {
	return nil
}
