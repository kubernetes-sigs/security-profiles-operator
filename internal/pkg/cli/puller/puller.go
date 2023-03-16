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

package puller

import (
	"fmt"
	"log"
	"os"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
)

// Puller is the main structure of this package.
type Puller struct {
	impl
	options *Options
}

// New returns a new Puller instance.
func New(options *Options) *Puller {
	return &Puller{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Puller.
func (p *Puller) Run() error {
	log.Printf("Pulling profile from: %s", p.options.pullFrom)

	result, err := p.Pull(
		p.options.pullFrom,
		p.options.username,
		p.options.password,
	)
	if err != nil {
		return fmt.Errorf("pull profile: %w", err)
	}

	name := ""
	switch result.Type() {
	case artifact.PullResultTypeSeccompProfile:
		name = result.SeccompProfile().GetName()

	case artifact.PullResultTypeSelinuxProfile:
		name = result.SelinuxProfile().GetName()

	case artifact.PullResultTypeApparmorProfile:
		name = result.ApparmorProfile().GetName()
	}
	log.Printf("Got %s: %s", result.Type(), name)

	log.Printf("Saving profile in: %s", p.options.outputFile)
	const defaultFileMode = os.FileMode(0o644)
	if err := p.WriteFile(
		p.options.outputFile, result.Content(), defaultFileMode,
	); err != nil {
		return fmt.Errorf("save profile: %w", err)
	}

	return nil
}
