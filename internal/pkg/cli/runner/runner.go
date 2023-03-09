//go:build linux
// +build linux

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

package runner

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/opencontainers/runtime-spec/specs-go"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
)

// Runner is the main structure of this package.
type Runner struct {
	impl
	options *Options
}

// New returns a new Runner instance.
func New(options *Options) *Runner {
	return &Runner{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Runner.
func (r *Runner) Run() error {
	log.Printf("Reading file %s", r.options.profile)
	content, err := r.ReadFile(r.options.profile)
	if err != nil {
		return fmt.Errorf("open profile: %w", err)
	}

	if filepath.Ext(r.options.profile) != seccompprofileapi.ExtJSON {
		log.Print("Assuming YAML profile")
		seccompProfile := &seccompprofileapi.SeccompProfile{}
		if err := r.YamlUnmarshal(content, seccompProfile); err != nil {
			return fmt.Errorf("unmarshal YAML profile: %w", err)
		}

		content, err = r.JSONMarshal(seccompProfile.Spec)
		if err != nil {
			return fmt.Errorf("remarshal JSON profile: %w", err)
		}
	}

	runtimeSpecConfig := &specs.LinuxSeccomp{}
	if err := r.JSONUnmarshal(content, runtimeSpecConfig); err != nil {
		return fmt.Errorf("unmarshal JSON profile: %w", err)
	}

	log.Print("Setting up seccomp")
	libConfig, err := r.SetupSeccomp(runtimeSpecConfig)
	if err != nil {
		return fmt.Errorf("convert profile: %w", err)
	}

	log.Print("Load seccomp profile")
	if _, err := r.InitSeccomp(libConfig); err != nil {
		return fmt.Errorf("init profile: %w", err)
	}

	cmd := command.New(r.options.commandOptions)
	if _, err := r.CommandRun(cmd); err != nil {
		return fmt.Errorf("run command: %w", err)
	}

	if err := r.CommandWait(cmd); err != nil {
		return fmt.Errorf("wait for command: %w", err)
	}

	return nil
}
