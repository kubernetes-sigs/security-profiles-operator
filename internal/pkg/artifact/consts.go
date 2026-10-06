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

	// MaxRuntimeProfileSize is the artifact size limit container runtimes
	// apply by default when they validate a KEP-6061 artifact. It is runtime
	// configuration rather than part of the format, so exceeding it is a
	// warning on push and not an error. Everything else runtimes reject is
	// checked with the merge library's ValidateArtifact and fails the push.
	// The operator daemon uses it as the blob size limit for base profiles,
	// since a bigger base profile could not be used by a runtime either.
	MaxRuntimeProfileSize int64 = 1 << 20

	// DefaultMaxBlobSize is the largest blob Pull copies from a registry
	// unless PullOptions.MaxBlobSize sets a limit. Pulled profiles are read
	// into memory, so the registry must not decide how much gets allocated.
	// The default is far above any real profile.
	DefaultMaxBlobSize int64 = 16 << 20

	// maxArtifactLayers is the most layers of an artifact, or manifests of an
	// index, a pull considers. Artifacts carry one profile per platform.
	maxArtifactLayers = 128

	// mediaTypeDockerManifest is the media type of a Docker image manifest,
	// which has the layout of an OCI image manifest.
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

	// mediaTypeDockerManifestList is the media type of a Docker manifest
	// list, which has the layout of an OCI image index.
	mediaTypeDockerManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"

	// dockerHubRegistryHost is the host ORAS reaches Docker Hub through.
	dockerHubRegistryHost = "registry-1.docker.io"

	// defaultTimeout is the default timeout for push and pull operations.
	defaultTimeout = 5 * time.Minute

	// bundleMediaType is the media type of a Sigstore bundle, which is the
	// artifact type of the referrer manifest a signature is attached with
	// and the media type of its only layer.
	bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// bundleMediaTypePrefix matches the media types of all Sigstore bundle
	// versions.
	bundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

	// cosignSignPredicateType is the predicate type of the in-toto statement
	// cosign signs for an image, as opposed to attestations like SLSA
	// provenance.
	cosignSignPredicateType = "https://sigstore.dev/cosign/sign/v1"

	// annotationBundlePredicateType is the referrer manifest annotation
	// which carries the predicate type of the bundle.
	annotationBundlePredicateType = "dev.sigstore.bundle.predicateType"

	// annotationBundleContent is the referrer manifest annotation which
	// carries the kind of content of the bundle.
	annotationBundleContent = "dev.sigstore.bundle.content"

	// bundleContentDSSE is the annotationBundleContent of a bundle with a
	// DSSE envelope.
	bundleContentDSSE = "dsse-envelope"

	// inTotoPayloadType is the DSSE payload type of an in-toto statement.
	inTotoPayloadType = "application/vnd.in-toto+json"

	// annotationLegacySignature, annotationLegacyCertificate and
	// annotationLegacyBundle are the layer annotations of a legacy cosign
	// signature: the base64 encoded signature of the layer, the PEM encoded
	// signing certificate and the transparency log entry.
	annotationLegacySignature   = "dev.cosignproject.cosign/signature"
	annotationLegacyCertificate = "dev.sigstore.cosign/certificate"
	annotationLegacyBundle      = "dev.sigstore.cosign/bundle"

	// legacySignatureTagSuffix is the suffix of the tag cosign v2 attaches
	// legacy signatures of a digest with.
	legacySignatureTagSuffix = ".sig"

	// maxSignatures is the most signatures of an artifact a pull fetches and
	// verifies, signature bundles or legacy signatures. Artifacts carry one
	// signature per signing, so a registry serving more cannot make the pull
	// fetch them all.
	maxSignatures = 16

	// maxReferrers is the most referrers of an artifact a pull lists while
	// looking for signature bundles, so that a registry cannot keep the pull
	// busy with endless pages of attestations.
	maxReferrers = 1000

	// maxReportedSignatureErrors is how many failed signatures the error of
	// a failed verification details, the others are only counted.
	maxReportedSignatureErrors = 3

	// maxSignatureSize is the largest signature bundle or legacy signature
	// payload a pull fetches.
	maxSignatureSize int64 = 1 << 20

	// maxSignatureManifestSize is the largest signature manifest a pull
	// fetches, the manifest limit of ORAS.
	maxSignatureManifestSize int64 = 4 << 20

	// annotationCreatedDefault is the org.opencontainers.image.created value
	// a pushed manifest carries unless the caller sets the annotation or
	// SOURCE_DATE_EPOCH. ORAS would stamp the current time, which makes
	// identical content produce a new digest on every push.
	annotationCreatedDefault = "1970-01-01T00:00:00Z"

	// envSourceDateEpoch is the reproducible-builds convention for the
	// timestamp to embed, in seconds since the Unix epoch.
	envSourceDateEpoch = "SOURCE_DATE_EPOCH"

	// OfficialSignerIdentityRegexp matches the identities which sign the
	// artifacts this project publishes: the service account of the staging
	// build and the Kubernetes image promoter, which signs everything it
	// promotes to registry.k8s.io.
	OfficialSignerIdentityRegexp = `^(sp-operator-sa@k8s-staging-images|krel-trust@k8s-releng-prod)` +
		`\.iam\.gserviceaccount\.com$`

	// OfficialSignerOidcIssuerRegexp matches the OIDC issuer of the official
	// signer identities.
	OfficialSignerOidcIssuerRegexp = `^https://accounts\.google\.com$`
)

// officialRepositories are the repository prefixes of the artifacts this
// project publishes. Pulls from them verify the official signers unless the
// caller changed the default signer regexps.
var officialRepositories = []string{
	"registry.k8s.io/security-profiles-operator/",
	"us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/",
}

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

	// ErrInvalidSourceDateEpoch is returned when SOURCE_DATE_EPOCH is set
	// but is not an integer number of seconds.
	ErrInvalidSourceDateEpoch = errors.New("SOURCE_DATE_EPOCH is not a number of seconds")

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

	// ErrBlobTooLarge is returned when a blob of the pulled artifact exceeds
	// the size limit of the pull.
	ErrBlobTooLarge = errors.New("artifact blob exceeds the size limit")

	// ErrPlatformMismatch is returned when the only layer of an artifact is
	// bound to another platform than the requested one.
	ErrPlatformMismatch = errors.New("artifact layer is bound to another platform")

	// ErrNoMatchingManifest is returned when an image index has no manifest
	// for the requested platform.
	ErrNoMatchingManifest = errors.New("image index has no manifest for the platform")

	// ErrTooManyLayers is returned when a pulled artifact has more layers, or
	// an index more manifests, than a pull considers.
	ErrTooManyLayers = errors.New("artifact has too many layers")

	// ErrNoSignature is returned when a pulled artifact has neither a
	// signature bundle nor a legacy signature.
	ErrNoSignature = errors.New("no signature found")

	// ErrSignatureVerification wraps every error of the signature
	// verification of a pull, so that callers can tell it apart from a
	// failure to reach the registry or to read the profile.
	ErrSignatureVerification = errors.New("verify signature")

	// ErrUnsupportedKeyRef is returned when the key to verify with is not a
	// PEM encoded public key file.
	ErrUnsupportedKeyRef = errors.New(
		"unsupported key reference, only PEM encoded public key files are supported",
	)

	// ErrInvalidSignatureBundle is returned when a signature is malformed.
	ErrInvalidSignatureBundle = errors.New("invalid signature")

	// ErrSignatureDigestMismatch is returned when a legacy signature is
	// about another digest than the pulled one.
	ErrSignatureDigestMismatch = errors.New("signature does not match the artifact digest")

	// ErrNoTrustedRoot is returned when no Sigstore trusted root is
	// available to verify with.
	ErrNoTrustedRoot = errors.New("no Sigstore trusted root")

	// ErrNoSigningConfig is returned when no Sigstore signing config is
	// available to sign with.
	ErrNoSigningConfig = errors.New("no Sigstore signing config")

	// ErrRekorV2WithoutTimestampAuthority is returned when the signing config
	// selects a Rekor v2 log without a timestamp authority.
	ErrRekorV2WithoutTimestampAuthority = errors.New(
		"a timestamp authority is required to sign with a certificate into a Rekor v2 log",
	)

	// ErrIDToken is returned when an identity token cannot be obtained.
	ErrIDToken = errors.New("unable to get an identity token")

	// ErrNoInteractiveSignIn is returned when signing needs an identity
	// token, the environment furnishes none and stdin is not a terminal for
	// an interactive sign in, while the device flow is not enabled.
	ErrNoInteractiveSignIn = errors.New(
		"no OIDC identity token in the environment and no terminal to sign in interactively",
	)
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
