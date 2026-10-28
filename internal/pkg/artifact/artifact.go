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

package artifact

import (
	"context"
	"strings"

	"github.com/go-logr/logr"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// PullResult is the type returned by Pull.
type PullResult struct {
	typ PullResultType

	seccompProfile  *seccompprofileapi.SeccompProfile
	selinuxProfile  *selinuxprofileapi.SelinuxProfile
	apparmorProfile *apparmorprofileapi.AppArmorProfile

	content       []byte
	runtimeFormat bool
}

// IsRuntimeFormat returns whether the content is a raw OCI runtime-spec
// seccomp profile in JSON: from an artifact in the KEP-6061 runtime format, or
// from an artifact of another media type which holds such a profile.
func (p *PullResult) IsRuntimeFormat() bool {
	return p.runtimeFormat
}

// Type returns the PullResultType of the PullResult.
func (p *PullResult) Type() PullResultType {
	return p.typ
}

// SeccompProfile returns the seccomp profile of the PullResult.
func (p *PullResult) SeccompProfile() *seccompprofileapi.SeccompProfile {
	return p.seccompProfile
}

// SelinuxProfile returns the selinux profile of the PullResult.
func (p *PullResult) SelinuxProfile() *selinuxprofileapi.SelinuxProfile {
	return p.selinuxProfile
}

// ApparmorProfile returns the apparmor profile of the PullResult.
func (p *PullResult) ApparmorProfile() *apparmorprofileapi.AppArmorProfile {
	return p.apparmorProfile
}

// Content returns the raw byte content of the profile.
func (p *PullResult) Content() []byte {
	return p.content
}

// Artifact is the main structure of this package.
type Artifact struct {
	impl
	logger logr.Logger
}

// KeylessSigner furnishes the Sigstore clients which Push and Sign need to
// sign keylessly. The signing package implements it, so that only the
// binaries which sign link these clients.
type KeylessSigner interface {
	// IDToken returns an identity token of the signer for the OIDC issuer,
	// with the device flow if deviceFlow is set and no terminal is there for
	// an interactive sign in.
	IDToken(ctx context.Context, issuer string, deviceFlow bool) (string, error)

	// DSSESigner selects the services of the signing config. The returned
	// function signs a DSSE payload of the payload type for the identity
	// token into a Sigstore bundle.
	DSSESigner(
		signingConfig *root.SigningConfig, material root.TrustedMaterial, token string,
	) (func(ctx context.Context, payload []byte, payloadType string) (*protobundle.Bundle, error), error)
}

// New returns a new Artifact instance, which does not sign. Sign, and Push
// unless signing is disabled, fail with ErrNoKeylessSigner.
func New(logger logr.Logger) *Artifact {
	return NewWithSigner(logger, nil)
}

// NewWithSigner returns a new Artifact instance which signs with the signer.
func NewWithSigner(logger logr.Logger, signer KeylessSigner) *Artifact {
	return &Artifact{
		impl:   &defaultImpl{signer: signer},
		logger: logger,
	}
}

// nameFromReference derives a profile name from an image reference by taking
// the last repository path element, so that pull results from runtime-spec
// artifacts, which carry no metadata, still have a name.
func nameFromReference(ref string) string {
	name, _, _ := strings.Cut(ref, "@")

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	name, _, _ = strings.Cut(name, ":")

	name = strings.Trim(
		invalidNameChars.ReplaceAllString(strings.ToLower(name), "-"), "-.",
	)
	if name == "" {
		return defaultProfileName
	}

	return name
}

// ProfileName returns the layer name for the platform.
func ProfileName(platform *v1.Platform) string {
	name := strings.Builder{}
	name.WriteString("profile")

	if platform != nil {
		for _, part := range []string{
			platform.OS,
			platform.Architecture,
			platform.Variant,
			platform.OSVersion,
		} {
			if part != "" {
				name.WriteRune('-')
				name.WriteString(part)
			}
		}
	}

	name.WriteString(extYAML)

	return name.String()
}

// platformToString returns a string for the provided platform.
func platformToString(platform *v1.Platform) string {
	if platform == nil {
		return ""
	}

	name := strings.Builder{}

	for i, part := range []string{
		platform.OS,
		platform.Architecture,
		platform.Variant,
	} {
		if part != "" {
			if i > 0 {
				name.WriteRune('/')
			}

			name.WriteString(part)
		}
	}

	if platform.OSVersion != "" {
		name.WriteRune(':')
		name.WriteString(platform.OSVersion)
	}

	return name.String()
}
