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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

const allowAllRegexp = ".*"

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

func (a *Artifact) setRepoCredentials(repo *remote.Repository, username, password string) {
	if username != "" && password != "" {
		a.logger.Info("Using username and password")

		repo.Client = &auth.Client{
			Client: retry.DefaultClient,
			Cache:  auth.DefaultCache,
			Credential: auth.StaticCredential(
				repo.Reference.Registry,
				auth.Credential{Username: username, Password: password},
			),
		}
	}
}

// PullSignatureOptions options for verifying the OCI image signature during pulling.
type PullSignatureOptions struct {
	// DisableSignatureVerification disables signature verification during pulling.
	DisableSignatureVerification bool

	// AllowedIdentityRegexp regexp for allowed identities for signature verification.
	AllowedIdentityRegexp string

	// AllowedOidcIssuerRegexp regexp for allowed Oidc issuer for signature verification.
	AllowedOidcIssuerRegexp string
}

// PushSignatureOptions options for signing the OCI artifact during pushing.
type PushSignatureOptions struct {
	// DisableSigning skips signing the artifact after it has been pushed.
	// Keyless signing needs an OIDC identity, which build systems and test
	// environments do not necessarily have.
	DisableSigning bool
}

// New returns a new Artifact instance.
func New(logger logr.Logger) *Artifact {
	return &Artifact{
		impl:   &defaultImpl{},
		logger: logger,
	}
}

// Push a profile to a remote location.
func (a *Artifact) Push(
	files map[*v1.Platform]string,
	to, username, password string,
	annotations map[string]string,
	signOpts *PushSignatureOptions,
) error {
	dir, err := a.MkdirTemp("", "push-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	defer func() {
		if err := a.RemoveAll(dir); err != nil {
			a.logger.Info("Unable to remove temp dir", "error", err)
		}
	}()

	a.logger.Info("Creating file store", "dir", dir)

	store, err := a.FileNew(dir)
	if err != nil {
		return fmt.Errorf("create file store: %w", err)
	}

	defer func() {
		if err := a.FileClose(store); err != nil {
			a.logger.Info("Unable to close file store", "error", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	a.logger.Info("Reading profiles", "count", len(files))

	entries, runtimeSpecProfiles, err := a.profileEntries(files)
	if err != nil {
		return err
	}

	if runtimeSpecProfiles > 0 && runtimeSpecProfiles != len(files) {
		return ErrMixedProfileFormats
	}

	if runtimeSpecProfiles > 1 {
		return ErrMultipleRuntimeSpecProfiles
	}

	fileDescriptors := []v1.Descriptor{}

	for _, entry := range entries {
		a.logger.Info("Adding profile to store",
			"file", entry.absPath,
			"platform", platformToString(entry.platform),
		)

		fileDescriptor, err := a.StoreAdd(
			ctx, store, entry.name, entry.layerMediaType, entry.absPath,
		)
		if err != nil {
			return fmt.Errorf("add profile to store: %w", err)
		}

		maps.Copy(fileDescriptor.Annotations, annotations)

		fileDescriptor.Platform = entry.platform
		fileDescriptors = append(fileDescriptors, fileDescriptor)
	}

	mediaType := oras.MediaTypeUnknownConfig
	packOptions := oras.PackManifestOptions{Layers: fileDescriptors}

	if runtimeSpecProfiles > 0 {
		mediaType = MediaTypeSeccompProfile

		configDescriptor, err := a.pushConfig(ctx, store, mediaType)
		if err != nil {
			return fmt.Errorf("push config: %w", err)
		}

		packOptions.ConfigDescriptor = &configDescriptor
	}

	a.logger.Info("Packing files", "mediaType", mediaType)

	manifestDescriptor, err := a.PackManifest(
		ctx,
		store,
		oras.PackManifestVersion1_1,
		mediaType,
		packOptions,
	)
	if err != nil {
		return fmt.Errorf("pack files: %w", err)
	}

	a.logger.Info("Verifying reference", "ref", to)

	parsedRef, err := a.ParseReference(to)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	tag := parsedRef.Identifier()

	a.logger.Info("Using tag", "tag", tag)

	if err = a.StoreTag(ctx, store, manifestDescriptor, tag); err != nil {
		return fmt.Errorf("creating tag: %w", err)
	}

	ref := parsedRef.Context().Name()
	a.logger.Info("Creating repository", "ref", ref)

	repo, err := a.NewRepository(ref)
	if err != nil {
		return fmt.Errorf("create repository: %w", err)
	}

	a.setRepoCredentials(repo, username, password)

	a.logger.Info("Copying profile to repository")

	descriptor, err := a.Copy(ctx, store, tag, repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("copy to repository: %w", err)
	}

	a.logger.Info("Pushed artifact", "reference", fmt.Sprintf("%s@%s", ref, descriptor.Digest))

	if signOpts != nil && signOpts.DisableSigning {
		a.logger.Info("Signing disabled, not signing the OCI artifact")

		return nil
	}

	a.logger.Info("Signing OCI artifact")

	o := &options.SignOptions{
		Upload:           true,
		TlogUpload:       true,
		SkipConfirmation: true,
		Rekor:            options.RekorOptions{URL: options.DefaultRekorURL},
		Fulcio:           options.FulcioOptions{URL: options.DefaultFulcioURL},
		OIDC: options.OIDCOptions{
			Issuer:   options.DefaultOIDCIssuerURL,
			ClientID: "sigstore",
		},
	}

	oidcClientSecret, err := a.ClientSecret(o.OIDC)
	if err != nil {
		return fmt.Errorf("get OIDC client secret: %w", err)
	}

	if err := a.SignCmd(
		&options.RootOptions{Timeout: defaultTimeout},
		options.KeyOpts{
			KeyRef:                         o.Key,
			PassFunc:                       generate.GetPass,
			Sk:                             o.SecurityKey.Use,
			Slot:                           o.SecurityKey.Slot,
			FulcioURL:                      o.Fulcio.URL,
			IDToken:                        o.Fulcio.IdentityToken,
			InsecureSkipFulcioVerify:       o.Fulcio.InsecureSkipFulcioVerify,
			RekorURL:                       o.Rekor.URL,
			OIDCIssuer:                     o.OIDC.Issuer,
			OIDCClientID:                   o.OIDC.ClientID,
			OIDCClientSecret:               oidcClientSecret,
			OIDCRedirectURL:                o.OIDC.RedirectURL,
			OIDCDisableProviders:           o.OIDC.DisableAmbientProviders,
			OIDCProvider:                   o.OIDC.Provider,
			SkipConfirmation:               o.SkipConfirmation,
			TSAServerURL:                   o.TSAServerURL,
			IssueCertificateForExistingKey: o.IssueCertificate,
		},
		*o,
		[]string{fmt.Sprintf("%s@%s", ref, descriptor.Digest)},
	); err != nil {
		return fmt.Errorf("sign image: %w", err)
	}

	return nil
}

// Pull a profile from a remote location.
func (a *Artifact) Pull(
	c context.Context,
	from, username, password string,
	platform *v1.Platform,
	signOpts *PullSignatureOptions,
) (*PullResult, error) {
	ctx, cancel := context.WithTimeout(c, defaultTimeout)
	defer cancel()

	originalImage := from

	a.logger.Info("Resolving digest of image", "image", originalImage)

	// Retrieve the immutable image digest before doing any verification to
	// prevent a TOCTOU attack on the mutable tag of the base image, which
	// might lead to a malicious base profile being injected between
	// verification and copying the content.
	from, repo, sha, err := a.imageWithDigest(ctx, originalImage, username, password)
	if err != nil {
		return nil, fmt.Errorf("resolving digest for image %q: %w", originalImage, err)
	}

	if signOpts == nil {
		signOpts = &PullSignatureOptions{
			AllowedIdentityRegexp:   allowAllRegexp,
			AllowedOidcIssuerRegexp: allowAllRegexp,
		}
	}

	if !signOpts.DisableSignatureVerification {
		a.logger.Info("Verifying signature")

		v := verify.VerifyCommand{
			CertVerifyOptions: options.CertVerifyOptions{
				CertIdentityRegexp:   signOpts.AllowedIdentityRegexp,
				CertOidcIssuerRegexp: signOpts.AllowedOidcIssuerRegexp,
			},
		}
		if err := a.VerifyCmd(ctx, v, from); err != nil {
			return nil, fmt.Errorf("verify signature: %w", err)
		}
	}

	dir, err := a.MkdirTemp("", "pull-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	defer func() {
		if err := a.RemoveAll(dir); err != nil {
			a.logger.Info("Unable to remove temp dir", "error", err)
		}
	}()

	a.logger.Info("Creating file store", "dir", dir)

	store, err := a.FileNew(dir)
	if err != nil {
		return nil, fmt.Errorf("create file store: %w", err)
	}

	defer func() {
		if err := a.FileClose(store); err != nil {
			a.logger.Info("Unable to close file store", "error", err)
		}
	}()

	a.logger.Info("Copying profile from repository")
	a.logger.Info("Source image", "image", from)

	manifestDescriptor, err := a.Copy(
		ctx, repo, sha.String(), store, sha.String(), oras.DefaultCopyOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("copy from repository: %w", err)
	}

	a.logger.Info("Checking profile contents")

	content, runtimeFormat, err := a.profileContent(
		ctx, store, dir, &manifestDescriptor, platform,
	)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	if runtimeFormat {
		spec, err := runtimeSpecSeccompProfileSpec(content)
		if err != nil {
			return nil, fmt.Errorf("decode %s artifact: %w", MediaTypeSeccompProfile, err)
		}

		return seccompPullResult(originalImage, spec, content, true), nil
	}

	profile, err := a.ReadProfile(content)
	if err != nil {
		// Artifacts without the KEP-6061 media type may still hold a raw
		// runtime-spec seccomp profile.
		spec, specErr := runtimeSpecSeccompProfileSpec(content)
		if specErr != nil {
			return nil, errors.Join(ErrDecodeYAML, err, specErr)
		}

		a.logger.Info("Profile is an OCI runtime-spec seccomp profile")

		return seccompPullResult(originalImage, spec, content, true), nil
	}

	switch obj := profile.(type) {
	case *seccompprofileapi.SeccompProfile:
		return &PullResult{
			typ:            PullResultTypeSeccompProfile,
			seccompProfile: obj,
			content:        content,
		}, nil
	case *selinuxprofileapi.SelinuxProfile:
		return &PullResult{
			typ:            PullResultTypeSelinuxProfile,
			selinuxProfile: obj,
			content:        content,
		}, nil
	case *apparmorprofileapi.AppArmorProfile:
		return &PullResult{
			typ:             PullResultTypeAppArmorProfile,
			apparmorProfile: obj,
			content:         content,
		}, nil
	default:
		return nil, fmt.Errorf("cannot process %T to PullResult", obj)
	}
}

// imageWithDigest transforms the given image into an image with digest instead of a tag.
// It retrieves the digest from the remote repository. Returns the updated image with
// digest and the repository and the digest as separate return arguments.
func (a *Artifact) imageWithDigest(ctx context.Context, image, username, password string) (
	string, *remote.Repository, digest.Digest, error,
) {
	ref, err := a.ParseReference(image)
	if err != nil {
		return "", nil, "", fmt.Errorf("parsing ref for image %q: %w", image, err)
	}

	repo, err := a.NewRepository(ref.Context().Name())
	if err != nil {
		return "", nil, "", fmt.Errorf("creating repository for %q: %w",
			ref.Name(), err)
	}

	a.setRepoCredentials(repo, username, password)

	desc, err := a.ResolveRepository(ctx, repo, ref.Identifier())
	if err != nil {
		return "", nil, "",
			fmt.Errorf("resolving image identifier %q: %w", ref.Identifier(), err)
	}

	return fmt.Sprintf("%s@%s", ref.Context().Name(),
		desc.Digest.String()), repo, desc.Digest, nil
}

// profileEntry is a profile to be added to the artifact store on push.
type profileEntry struct {
	platform       *v1.Platform
	absPath        string
	name           string
	layerMediaType string
	runtimeSpec    bool
}

// profileEntries reads the provided files and derives the layer name and
// media type for each of them. It also returns how many of them are raw OCI
// runtime-spec seccomp profiles.
func (a *Artifact) profileEntries(
	files map[*v1.Platform]string,
) ([]profileEntry, int, error) {
	entries := make([]profileEntry, 0, len(files))
	runtimeSpecProfiles := 0

	for platform, file := range files {
		absPath, err := a.FilepathAbs(file)
		if err != nil {
			return nil, 0, fmt.Errorf("get absolute file path: %w", err)
		}

		content, err := a.ReadFile(absPath)
		if err != nil {
			return nil, 0, fmt.Errorf("read profile: %w", err)
		}

		entry := profileEntry{
			platform: platform,
			absPath:  absPath,
			name:     profileName(platform),
		}

		runtimeSpec, isRuntimeSpec, err := a.runtimeSpecSeccompProfile(content)
		if err != nil {
			return nil, 0, fmt.Errorf("profile %s: %w", file, err)
		}

		if isRuntimeSpec {
			a.logger.Info("Profile is an OCI runtime-spec seccomp profile", "file", file)
			a.warnRuntimeRestrictions(runtimeSpec, content, file)

			// KEP-6061 artifacts hold exactly one platform independent
			// profile, so the layer is neither named nor tagged per platform.
			if platform != nil {
				a.logger.Info(
					"Ignoring platform, runtime format artifacts are platform independent",
					"file", file,
					"platform", platformToString(platform),
				)
			}

			runtimeSpecProfiles++
			entry.runtimeSpec = true
			entry.platform = nil
			entry.name = defaultProfileJSON
			entry.layerMediaType = layerMediaTypeJSON
		}

		entries = append(entries, entry)
	}

	return entries, runtimeSpecProfiles, nil
}

// pushConfig pushes the manifest config blob of a runtime format artifact to
// the store and returns its descriptor. ORAS defaults to the empty OCI config
// descriptor, which would leave the media type identifying the artifact in
// the manifest artifactType field only.
func (a *Artifact) pushConfig(
	ctx context.Context, store *file.Store, mediaType string,
) (v1.Descriptor, error) {
	descriptor := v1.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(emptyConfig),
		Size:      int64(len(emptyConfig)),
	}

	if err := a.StorePush(ctx, store, descriptor, bytes.NewReader(emptyConfig)); err != nil {
		return v1.Descriptor{}, fmt.Errorf("store config blob: %w", err)
	}

	return descriptor, nil
}

// profileContent returns the profile content of a pulled artifact, together
// with whether the artifact uses the KEP-6061 runtime format. It prefers the
// layer names used by push, but falls back to the single layer of the
// artifact because KEP-6061 mandates no particular layer name.
func (a *Artifact) profileContent(
	ctx context.Context,
	store *file.Store,
	dir string,
	manifestDescriptor *v1.Descriptor,
	platform *v1.Platform,
) (content []byte, runtimeFormat bool, err error) {
	manifest, err := a.manifest(ctx, store, manifestDescriptor)
	if err != nil {
		return nil, false, err
	}

	// KEP-6061 identifies the artifact by the config media type, with the
	// artifact type as fallback for the empty OCI config descriptor.
	if manifest.Config.MediaType == MediaTypeSeccompProfile ||
		manifest.ArtifactType == MediaTypeSeccompProfile {
		a.logger.Info("Artifact is in the runtime format", "mediaType", MediaTypeSeccompProfile)

		if len(manifest.Layers) != 1 {
			return nil, false, fmt.Errorf("%w: got %d", ErrNoSingleLayer, len(manifest.Layers))
		}

		content, err := a.blobContent(ctx, store, &manifest.Layers[0])

		return content, true, err
	}

	// profileName falls back to defaultProfileYAML if no platform is
	// available, so only look for it separately if there is one.
	names := []string{profileName(platform)}
	if platform != nil {
		names = append(names, defaultProfileYAML)
	}

	names = append(names, defaultProfileJSON)

	for _, name := range names {
		a.logger.Info("Trying to read profile", "name", name)

		if content, err := a.ReadFile(filepath.Join(dir, name)); err == nil {
			return content, false, nil
		}
	}

	content, err = a.singleLayerContent(ctx, store, manifest, platform)

	return content, false, err
}

// singleLayerContent returns the content of the only layer of an artifact,
// which is the fallback for artifacts not using a layer name push produces.
// It reads the layer through its descriptor, because KEP-6061 requires
// neither a layer name nor the annotation the ORAS file store needs to
// materialize a layer on disk. A layer bound to another platform is not
// eligible, it would have been found by name for a matching one.
func (a *Artifact) singleLayerContent(
	ctx context.Context, store *file.Store, manifest *v1.Manifest, platform *v1.Platform,
) ([]byte, error) {
	if len(manifest.Layers) != 1 {
		return nil, fmt.Errorf("%w: got %d", ErrNoSingleLayer, len(manifest.Layers))
	}

	layer := &manifest.Layers[0]
	title := layer.Annotations[v1.AnnotationTitle]

	if !layerMatchesPlatform(layer, platform) {
		return nil, fmt.Errorf("%w: %s", ErrPlatformMismatch, title)
	}

	a.logger.Info("Falling back to single artifact layer", "title", title)

	return a.blobContent(ctx, store, layer)
}

// layerMatchesPlatform reports whether the layer can be used for the
// requested platform. Layers without a platform are only eligible if they are
// not named for one either.
func layerMatchesPlatform(layer *v1.Descriptor, platform *v1.Platform) bool {
	if layer.Platform == nil {
		return !platformQualifiedName.MatchString(layer.Annotations[v1.AnnotationTitle])
	}

	return platform != nil &&
		layer.Platform.OS == platform.OS &&
		layer.Platform.Architecture == platform.Architecture &&
		layer.Platform.Variant == platform.Variant &&
		layer.Platform.OSVersion == platform.OSVersion
}

// manifest returns the parsed manifest of a pulled artifact.
func (a *Artifact) manifest(
	ctx context.Context, store *file.Store, descriptor *v1.Descriptor,
) (*v1.Manifest, error) {
	content, err := a.blobContent(ctx, store, descriptor)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	manifest := &v1.Manifest{}
	if err := json.Unmarshal(content, manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	return manifest, nil
}

// blobContent returns the content of a blob from the store.
func (a *Artifact) blobContent(
	ctx context.Context, store *file.Store, descriptor *v1.Descriptor,
) ([]byte, error) {
	reader, err := a.StoreFetch(ctx, store, *descriptor)
	if err != nil {
		return nil, fmt.Errorf("fetch blob: %w", err)
	}

	defer func() {
		if err := reader.Close(); err != nil {
			a.logger.Info("Unable to close blob reader", "error", err)
		}
	}()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read blob: %w", err)
	}

	return content, nil
}

// seccompPullResult builds the PullResult for a raw OCI runtime-spec seccomp
// profile, which carries no metadata of its own.
func seccompPullResult(
	image string,
	spec *seccompprofileapi.SeccompProfileSpec,
	content []byte,
	runtimeFormat bool,
) *PullResult {
	return &PullResult{
		typ: PullResultTypeSeccompProfile,
		seccompProfile: &seccompprofileapi.SeccompProfile{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SeccompProfile",
				APIVersion: seccompprofileapi.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: nameFromReference(image),
			},
			Spec: *spec,
		},
		content:       content,
		runtimeFormat: runtimeFormat,
	}
}

// runtimeSpecSeccompProfile reports whether content is a raw OCI runtime-spec
// seccomp profile and returns it if so. A profile CRD is not one, but content
// which is neither is an error, publishing it would create an artifact no
// consumer understands.
func (a *Artifact) runtimeSpecSeccompProfile(
	content []byte,
) (*specs.LinuxSeccomp, bool, error) {
	_, profileErr := a.ReadProfile(content)
	if profileErr == nil {
		return nil, false, nil
	}

	runtimeSpec, err := decodeRuntimeSpecSeccompProfile(content)
	if err != nil {
		return nil, false, errors.Join(ErrDecodeYAML, profileErr, err)
	}

	return runtimeSpec, true, nil
}

// warnRuntimeRestrictions logs the parts of a profile which container
// runtimes reject when they validate a KEP-6061 artifact.
func (a *Artifact) warnRuntimeRestrictions(
	runtimeSpec *specs.LinuxSeccomp, content []byte, path string,
) {
	if runtimeSpec.ListenerPath != "" || runtimeSpec.ListenerMetadata != "" {
		a.logger.Info(
			"Profile sets listener fields, which container runtimes reject",
			"file", path,
		)
	}

	if usesNotify(runtimeSpec) {
		a.logger.Info(
			"Profile uses "+string(specs.ActNotify)+", which container runtimes reject",
			"file", path,
		)
	}

	if len(content) > maxProfileSize {
		a.logger.Info(
			"Profile is larger than container runtimes accept by default",
			"file", path,
			"size", len(content),
			"limit", maxProfileSize,
		)
	}

	if syscall := exceedsSyscallEntries(runtimeSpec); syscall != "" {
		a.logger.Info(
			"Profile has more entries for a syscall than container runtimes accept by default",
			"file", path,
			"syscall", syscall,
			"limit", maxSyscallEntries,
		)
	}
}

// exceedsSyscallEntries returns the first syscall which is referenced by more
// rule entries than container runtimes accept, and an empty string if there
// is none.
func exceedsSyscallEntries(runtimeSpec *specs.LinuxSeccomp) string {
	entries := map[string]int{}

	for i := range runtimeSpec.Syscalls {
		for _, name := range runtimeSpec.Syscalls[i].Names {
			entries[name]++

			if entries[name] > maxSyscallEntries {
				return name
			}
		}
	}

	return ""
}

// usesNotify reports whether the profile relies on a seccomp notifier.
func usesNotify(runtimeSpec *specs.LinuxSeccomp) bool {
	if runtimeSpec.DefaultAction == specs.ActNotify {
		return true
	}

	for i := range runtimeSpec.Syscalls {
		if runtimeSpec.Syscalls[i].Action == specs.ActNotify {
			return true
		}
	}

	return false
}

// decodeRuntimeSpecSeccompProfile decodes the content of a KEP-6061 artifact,
// a raw OCI runtime-spec seccomp profile. The content has to decode strictly
// into the runtime-spec type, so unknown fields and trailing data are
// rejected and defaultAction is required.
func decodeRuntimeSpecSeccompProfile(content []byte) (*specs.LinuxSeccomp, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	runtimeSpec := &specs.LinuxSeccomp{}
	if err := decoder.Decode(runtimeSpec); err != nil {
		return nil, fmt.Errorf("decode runtime-spec seccomp profile: %w", err)
	}

	if decoder.More() {
		return nil, ErrTrailingData
	}

	if runtimeSpec.DefaultAction == "" {
		return nil, ErrNoDefaultAction
	}

	return runtimeSpec, nil
}

// runtimeSpecSeccompProfileSpec converts the content of a KEP-6061 artifact
// into a SeccompProfileSpec. Fields the CRD cannot express, such as
// defaultErrnoRet, are dropped in the conversion. Values which do not fit the
// CRD, for example syscall argument values beyond the signed 64 bit range,
// are an error. Detection on push does not use this conversion, so profiles
// the CRD cannot hold are still published in the right format.
func runtimeSpecSeccompProfileSpec(
	content []byte,
) (*seccompprofileapi.SeccompProfileSpec, error) {
	if _, err := decodeRuntimeSpecSeccompProfile(content); err != nil {
		return nil, err
	}

	spec := &seccompprofileapi.SeccompProfileSpec{}
	if err := json.Unmarshal(content, spec); err != nil {
		return nil, fmt.Errorf("convert runtime-spec seccomp profile: %w", err)
	}

	return spec, nil
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
