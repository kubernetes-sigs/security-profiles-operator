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
	"errors"
	"regexp"
	"time"
)

const (
	// defaultProfileYAML is the default name for the OCI artifact profile.
	defaultProfileYAML = "profile.yaml"

	// defaultProfileJSON is the layer name of an OCI runtime-spec seccomp
	// profile artifact as consumed by container runtimes (KEP-6061). Those
	// artifacts carry exactly one platform independent profile, so the name
	// is not platform qualified.
	defaultProfileJSON = "profile.json"

	// defaultProfileName is the object name given to runtime-spec profiles
	// when none can be derived from the artifact reference.
	defaultProfileName = "profile"

	// MediaTypeSeccompProfile identifies an artifact whose single layer is an
	// OCI runtime-spec seccomp profile in JSON, as consumed by container
	// runtimes (KEP-6061). It is set as the manifest config media type as
	// well as the manifest artifact type.
	MediaTypeSeccompProfile = "application/vnd.cncf.seccomp-profile.config.v1+json"

	// extYAML is the layer name extension of profile CRDs.
	extYAML = ".yaml"

	// layerMediaTypeJSON is the layer media type of raw JSON profiles.
	layerMediaTypeJSON = "application/json"

	// maxProfileSize is the artifact size limit container runtimes apply by
	// default when they validate a KEP-6061 artifact. It is runtime
	// configuration rather than part of the format, so exceeding it is a
	// warning on push and not an error. Everything else runtimes reject is
	// checked with the merge library's ValidateArtifact and fails the push.
	maxProfileSize = 1 << 20

	// defaultTimeout is the default timeout for push and pull operations.
	defaultTimeout = 5 * time.Minute
)

// emptyConfig is the content of the manifest config blob of a runtime format
// artifact. The profile itself is the layer, the config only carries the
// media type which identifies the artifact.
var emptyConfig = []byte("{}")

// platformQualifiedName matches the layer names profileName generates for a
// platform.
var platformQualifiedName = regexp.MustCompile(
	`^profile-.+` + regexp.QuoteMeta(extYAML) + `$`,
)

// invalidNameChars matches everything which is not allowed in a Kubernetes
// object name.
var invalidNameChars = regexp.MustCompile(`[^a-z0-9.-]+`)

var (
	// ErrDecodeYAML is the error returned if no matching type could be decoded on
	// artifact pull.
	ErrDecodeYAML = errors.New(
		"unable to decode YAML or JSON into seccomp, selinux or apparmor profile",
	)

	// ErrNoKind is returned when a profile CRD has no kind.
	ErrNoKind = errors.New("invalid yaml, kind missing")

	// ErrNoDefaultAction is returned when a raw runtime-spec seccomp profile
	// has no defaultAction.
	ErrNoDefaultAction = errors.New("runtime-spec seccomp profile has no defaultAction")

	// ErrTrailingData is returned when a raw runtime-spec seccomp profile is
	// followed by additional data.
	ErrTrailingData = errors.New("trailing data after runtime-spec seccomp profile")

	// ErrRuntimeRestrictions is returned when a runtime-spec seccomp profile
	// contains content container runtimes reject in a KEP-6061 artifact, such
	// as SCMP_ACT_NOTIFY, listener settings or too many entries for one
	// syscall.
	ErrRuntimeRestrictions = errors.New(
		"runtime-spec seccomp profile is rejected by container runtimes",
	)

	// ErrMultipleRuntimeSpecProfiles is returned when more than one OCI
	// runtime-spec seccomp profile is pushed into one artifact, which must
	// contain exactly one layer.
	ErrMultipleRuntimeSpecProfiles = errors.New(
		"runtime-spec seccomp profile artifacts must contain exactly one profile",
	)

	// ErrMixedProfileFormats is returned when OCI runtime-spec seccomp
	// profiles and profile CRDs are pushed into the same artifact.
	ErrMixedProfileFormats = errors.New(
		"cannot mix runtime-spec seccomp profiles and profile CRDs in one artifact",
	)

	// ErrNoSingleLayer is returned when an artifact without a known profile
	// layer name does not have exactly one layer to fall back to.
	ErrNoSingleLayer = errors.New("artifact has no single layer to read the profile from")

	// ErrPlatformMismatch is returned when the only layer of an artifact is
	// bound to another platform than the requested one.
	ErrPlatformMismatch = errors.New("artifact layer is bound to another platform")
)

// PullResultType are the different types returned for a PullResult.
type PullResultType string

const (
	// PullResultTypeSeccompProfile is referencing a seccomp profile.
	PullResultTypeSeccompProfile PullResultType = "SeccompProfile"

	// PullResultTypeSelinuxProfile is referencing a SELinux profile.
	PullResultTypeSelinuxProfile PullResultType = "SelinuxProfile"

	// PullResultTypeAppArmorProfile is referencing an AppArmor profile.
	PullResultTypeAppArmorProfile PullResultType = "AppArmorProfile"
)
