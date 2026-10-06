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

package pusher

import (
	"errors"
	"fmt"
	"log"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
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
	log.Printf("Pushing profiles to: %s", p.options.pushTo)

	ctx, stop := cli.SignalContext()
	defer stop()

	if err := p.Push(
		ctx,
		p.options.inputFiles,
		p.options.pushTo,
		p.options.username,
		p.options.password,
		p.options.annotations,
		&artifact.PushOptions{
			DisableSigning:            p.options.disableSigning,
			DisableArtifactValidation: p.options.disableArtifactValidation,
			PlainHTTP:                 p.options.plainHTTP,
			OIDCDeviceFlow:            p.options.oidcDeviceFlow,
		},
	); err != nil {
		return fmt.Errorf("push profile: %w", withSigningHint(err))
	}

	return nil
}

// withSigningHint adds how to go on to a signing error: sign the pushed
// artifact afterwards, or push without signature if there is no identity.
func withSigningHint(err error) error {
	if unsigned, ok := errors.AsType[*artifact.UnsignedError](err); ok {
		return fmt.Errorf(
			"%w; once the cause is fixed, sign it with `spoc sign %s`",
			err, unsigned.Reference,
		)
	}

	if errors.Is(err, artifact.ErrNoInteractiveSignIn) {
		return fmt.Errorf(
			"%w; set SIGSTORE_ID_TOKEN, pass --%s to sign in with the device flow "+
				"or --%s to push without signature",
			err, FlagOIDCDeviceFlow, FlagDisableSigning,
		)
	}

	return err
}
