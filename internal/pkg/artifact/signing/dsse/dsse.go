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

// Package dsse signs DSSE payloads into Sigstore bundles. The signing package
// signs with it, and so do the tests of the artifact package, which cannot
// import the signing package.
package dsse

import (
	"context"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// Sign signs the payload of the payload type with an ephemeral key into a
// Sigstore bundle, with the services of the options. The context applies to
// the requests to these services.
func Sign(
	ctx context.Context, opts *sign.BundleOptions, payload []byte, payloadType string,
) (*protobundle.Bundle, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}

	bundleOpts := *opts
	bundleOpts.Context = ctx

	return sign.Bundle(&sign.DSSEData{Data: payload, PayloadType: payloadType}, keypair, bundleOpts)
}
