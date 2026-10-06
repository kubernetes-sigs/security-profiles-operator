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
	"strings"

	"github.com/go-logr/logr"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

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

// IsRuntimeFormat returns whether the artifact used the KEP-6061 runtime
// format, which means that the content is raw runtime-spec JSON.
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

// New returns a new Artifact instance.
func New(logger logr.Logger) *Artifact {
	return &Artifact{
		impl:   &defaultImpl{},
		logger: logger,
	}
}

// nameFromReference derives a profile name from an image reference by taking
// the last repository path element, so that pull results from runtime-spec
// artifacts, which carry no metadata, still have a name.
func nameFromReference(ref string) string {
	name := ref
	if idx := strings.Index(name, "@"); idx >= 0 {
		name = name[:idx]
	}

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	if idx := strings.Index(name, ":"); idx >= 0 {
		name = name[:idx]
	}

	name = strings.Trim(
		invalidNameChars.ReplaceAllString(strings.ToLower(name), "-"), "-.",
	)
	if name == "" {
		return defaultProfileName
	}

	return name
}

// profileName returns the layer name for the platform.
func profileName(platform *v1.Platform) string {
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
