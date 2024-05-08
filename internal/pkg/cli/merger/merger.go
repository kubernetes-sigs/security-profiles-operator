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

package merger

import (
	"bytes"
	"fmt"
	"log"

	"k8s.io/cli-runtime/pkg/printers"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
)

// Merger is the main structure of this package.
type Merger struct {
	impl
	options *Options
}

// New returns a new Merger instance.
func New(options *Options) *Merger {
	return &Merger{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Merger.
func (p *Merger) Run() error {
	log.Printf("Merging %d profiles into %s", len(p.options.inputFiles), p.options.outputFile)

	contents := make([]client.Object, len(p.options.inputFiles))
	for i, filepath := range p.options.inputFiles {
		log.Printf("Reading file %s", filepath)
		content, err := p.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("open profile: %w", err)
		}

		contents[i], err = artifact.ReadProfile(content)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", filepath, err)
		}
	}

	merged, err := recordingmerger.MergeProfiles(contents)
	if err != nil {
		return fmt.Errorf("merge profiles: %w", err)
	}

	var buffer bytes.Buffer
	printer := printers.YAMLPrinter{}
	if err := printer.PrintObj(merged, &buffer); err != nil {
		return fmt.Errorf("print YAML: %w", err)
	}
	const filePermissions = 0o600
	if err := p.WriteFile(p.options.outputFile, buffer.Bytes(), filePermissions); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
