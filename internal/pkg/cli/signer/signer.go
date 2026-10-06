/*
Copyright The Kubernetes Authors.

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

package signer

import (
	"errors"
	"fmt"
	"log"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// Signer is the main structure of this package.
type Signer struct {
	impl
	options *Options
}

// New returns a new Signer instance.
func New(options *Options) *Signer {
	return &Signer{
		impl:    &defaultImpl{},
		options: options,
	}
}

// Run the Signer.
func (s *Signer) Run() error {
	log.Printf("Signing: %s", s.options.image)

	ctx, stop := cli.SignalContext()
	defer stop()

	err := s.Sign(
		ctx,
		s.options.image,
		s.options.username,
		s.options.password,
		&artifact.SignOptions{
			PlainHTTP:      s.options.plainHTTP,
			OIDCDeviceFlow: s.options.oidcDeviceFlow,
		},
	)
	if errors.Is(err, artifact.ErrNoInteractiveSignIn) {
		return fmt.Errorf(
			"sign artifact: %w; set SIGSTORE_ID_TOKEN or pass --%s to sign in with the device flow",
			err, FlagOIDCDeviceFlow,
		)
	}

	if err != nil {
		return fmt.Errorf("sign artifact: %w", err)
	}

	return nil
}
