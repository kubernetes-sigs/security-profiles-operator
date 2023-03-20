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

package pusher

import (
	"fmt"
	"log"
)

// Pusher is the main structure of this package.
type Pusher struct {
	impl
	options *Options
}

// New returns a new Pusher instance.
func New(options *Options) *Pusher {
	return &Pusher{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Pusher.
func (p *Pusher) Run() error {
	log.Printf(
		"Pushing profile %s to: %s",
		p.options.inputFile, p.options.pushTo,
	)

	if err := p.Push(
		p.options.inputFile,
		p.options.pushTo,
		p.options.username,
		p.options.password,
		p.options.annotations,
	); err != nil {
		return fmt.Errorf("push profile: %w", err)
	}

	return nil
}
