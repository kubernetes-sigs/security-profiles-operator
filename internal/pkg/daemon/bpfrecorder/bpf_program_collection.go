//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package bpfrecorder

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"
)

type bpfProgram struct {
	name string
	prog *bpf.BPFProg
	link *bpf.BPFLink
}

// This struct holds a set of bpf programs so that they be quickly attached and detached.
// We want to minimize the time that takes because it races with container startup,
// and we want to make sure that we catch the entire container lifecycle.
type bpfProgramCollection struct {
	logger   logr.Logger
	programs []bpfProgram
}

func newProgramCollection(
	r *BpfRecorder,
	logger logr.Logger,
	module *bpf.Module,
	programNames []string,
) (*bpfProgramCollection, error) {
	programs := make([]bpfProgram, len(programNames))
	for i, name := range programNames {
		prog, err := r.GetProgram(module, name)
		if err != nil {
			return nil, fmt.Errorf("get bpf program %s: %w", name, err)
		}
		programs[i] = bpfProgram{
			name: name,
			prog: prog,
			link: nil,
		}
	}
	return &bpfProgramCollection{
		logger:   logger,
		programs: programs,
	}, nil
}

func (b *bpfProgramCollection) attachAll(r *BpfRecorder) error {
	var err error
	for i := range b.programs {
		b.programs[i].link, err = r.AttachGeneric(b.programs[i].prog)
		if err != nil {
			return fmt.Errorf("attach bpf program %s: %w", b.programs[i].name, err)
		}
		b.logger.Info("attached bpf program", "name", b.programs[i].name)
	}
	return err
}

func (b *bpfProgramCollection) detachAll(r *BpfRecorder) error {
	for i := range b.programs {
		if err := r.DestroyLink(b.programs[i].link); err != nil {
			return fmt.Errorf("detach bpf program %s: %w", b.programs[i].name, err)
		}
		b.programs[i].link = nil
		b.logger.Info("detached bpf program", "name", b.programs[i].name)
	}
	return nil
}
