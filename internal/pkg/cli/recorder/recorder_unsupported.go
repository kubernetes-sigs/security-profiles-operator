//go:build !linux || no_bpf
// +build !linux no_bpf

/*
Copyright 2023 The Kubernetes Authors.

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

package recorder

import (
	"errors"
)

var errUnsupported = errors.New("binary got compiled without bpf recorder support")

// Recorder is the main structure of this package.
type Recorder struct{}

// New returns a new Recorder instance.
func New(*Options) *Recorder {
	return &Recorder{}
}

// Run the Recorder.
func (r *Recorder) Run() error {
	return errUnsupported
}
