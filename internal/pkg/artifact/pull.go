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
	"encoding/json"
	"errors"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// Pull a profile from a remote location.
func (a *Artifact) Pull(
	c context.Context,
	from, username, password string,
	platform *v1.Platform,
	signOpts *PullOptions,
) (*PullResult, error) {
	ctx, cancel := context.WithTimeout(c, defaultTimeout)
	defer cancel()

	if signOpts == nil {
		signOpts = &PullOptions{}
	}

	originalImage := from
	signOpts = signOpts.withDefaultSigner(originalImage)

	if !signOpts.DisableSignatureVerification &&
		isOfficialArtifact(originalImage) && signOpts.hasCustomSigner() {
		// Verified as requested, the caller may have mirrored and re-signed
		// the artifact, but the official signature will not match.
		a.logger.Info(
			"Verifying an artifact of an official repository with a custom signer or trusted root, "+
				"official artifacts are signed keyless by the official signers through the public Sigstore instance",
			"image",
			originalImage,
		)
	}

	a.logger.Info("Resolving digest of image", "image", originalImage)

	// Retrieve the immutable image digest before doing any verification to
	// prevent a TOCTOU attack on the mutable tag of the base image, which
	// might lead to a malicious base profile being injected between
	// verification and copying the content.
	from, repo, subject, err := a.imageWithDigest(
		ctx, originalImage, username, password, signOpts.PlainHTTP,
	)
	if err != nil {
		return nil, fmt.Errorf("resolving digest for image %q: %w", originalImage, err)
	}

	if !signOpts.DisableSignatureVerification {
		if err := a.verifySignature(ctx, originalImage, repo, &subject, signOpts); err != nil {
			return nil, err
		}
	}

	content, runtimeFormat, err := a.fetchProfile(ctx, repo, from, &subject, platform, signOpts)
	if err != nil {
		return nil, err
	}

	return a.pullResult(originalImage, content, runtimeFormat)
}

// fetchProfile copies the manifest of the subject for the platform and its
// profile layer from the repository, and returns the profile content together
// with whether the artifact uses the KEP-6061 runtime format.
func (a *Artifact) fetchProfile(
	ctx context.Context,
	repo *remote.Repository,
	from string,
	subject *v1.Descriptor,
	platform *v1.Platform,
	signOpts *PullOptions,
) (content []byte, runtimeFormat bool, err error) {
	dir, err := a.MkdirTemp("", "pull-")
	if err != nil {
		return nil, false, fmt.Errorf("create temp dir: %w", err)
	}

	defer func() {
		if err := a.RemoveAll(dir); err != nil {
			a.logger.Info("Unable to remove temp dir", "error", err)
		}
	}()

	a.logger.Info("Creating file store", "dir", dir)

	store, err := a.FileNew(dir)
	if err != nil {
		return nil, false, fmt.Errorf("create file store: %w", err)
	}

	defer func() {
		if err := a.FileClose(store); err != nil {
			a.logger.Info("Unable to close file store", "error", err)
		}
	}()

	a.logger.Info("Copying profile from repository")
	a.logger.Info("Source image", "image", from)

	// Only the manifest for the platform and its profile layer get copied,
	// so that the size limit per blob bounds the whole pull.
	selection := &layerSelection{platform: platform}
	copyOptions := oras.DefaultCopyOptions
	copyOptions.PreCopy = blobSizeLimit(signOpts.maxBlobSize())
	copyOptions.MapRoot = selectManifest(platform, signOpts.maxBlobSize())
	copyOptions.FindSuccessors = selection.findSuccessors

	sha := subject.Digest.String()

	manifestDescriptor, err := a.Copy(ctx, repo, sha, store, sha, copyOptions)
	if err != nil {
		return nil, false, fmt.Errorf("copy from repository: %w", err)
	}

	a.logger.Info("Checking profile contents")

	content, runtimeFormat, err = a.profileContent(ctx, store, &manifestDescriptor, selection)
	if err != nil {
		return nil, false, fmt.Errorf("read profile: %w", err)
	}

	return content, runtimeFormat, nil
}

// pullResult decodes the pulled profile content.
func (a *Artifact) pullResult(
	originalImage string,
	content []byte,
	runtimeFormat bool,
) (*PullResult, error) {
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
// digest, the repository and the descriptor of the manifest the image resolves to.
func (a *Artifact) imageWithDigest(
	ctx context.Context, image, username, password string, plainHTTP bool,
) (string, *remote.Repository, v1.Descriptor, error) {
	ref, err := a.ParseReference(image)
	if err != nil {
		return "", nil, v1.Descriptor{}, fmt.Errorf("parsing ref for image %q: %w", image, err)
	}

	repo, err := a.NewRepository(ref.Context().Name())
	if err != nil {
		return "", nil, v1.Descriptor{}, fmt.Errorf("creating repository for %q: %w",
			ref.Name(), err)
	}

	repo.PlainHTTP = plainHTTP

	a.setRepoCredentials(repo, username, password)

	desc, err := a.ResolveRepository(ctx, repo, ref.Identifier())
	if err != nil {
		return "", nil, v1.Descriptor{},
			fmt.Errorf("resolving image identifier %q: %w", ref.Identifier(), err)
	}

	return fmt.Sprintf("%s@%s", ref.Context().Name(),
		desc.Digest.String()), repo, desc, nil
}

// blobSizeLimit returns the ORAS PreCopy hook which rejects every blob of the
// artifact larger than limit before it is fetched. ORAS reads the manifest
// first to find the blobs, bounded by its own metadata limit, and runs the
// hook on the manifest as well before storing it. The store then enforces the
// descriptor sizes while copying, so nothing bigger reaches the profile
// decoding either.
func blobSizeLimit(limit int64) func(context.Context, v1.Descriptor) error {
	return func(_ context.Context, desc v1.Descriptor) error {
		if desc.Size > limit {
			return fmt.Errorf(
				"%w: blob %s (%s) has %d bytes, limit is %d",
				ErrBlobTooLarge, desc.Digest, desc.MediaType, desc.Size, limit,
			)
		}

		return nil
	}
}

// profileContent returns the profile content of a pulled artifact, together
// with whether the artifact uses the KEP-6061 runtime format. The layer is the
// one the copy selected. If the copy did not select one, for example because
// it found the manifest in the store already, it gets selected from the
// stored manifest.
func (a *Artifact) profileContent(
	ctx context.Context,
	store *file.Store,
	manifestDescriptor *v1.Descriptor,
	selection *layerSelection,
) (content []byte, runtimeFormat bool, err error) {
	layer, runtimeFormat, ok := selection.result()
	if !ok {
		manifest, err := a.manifest(ctx, store, manifestDescriptor)
		if err != nil {
			return nil, false, err
		}

		layer, runtimeFormat, err = selectLayer(manifest, selection.platform)
		if err != nil {
			return nil, false, err
		}
	}

	a.logger.Info("Reading profile layer",
		"title", layer.Annotations[v1.AnnotationTitle],
		"runtimeFormat", runtimeFormat,
	)

	content, err = a.blobContent(ctx, store, layer)

	return content, runtimeFormat, err
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

// blobContent returns the content of a blob from the store. The read is
// bounded by the size limit of the pull: the store verified every blob
// against its descriptor on copy, and the descriptors passed blobSizeLimit.
func (a *Artifact) blobContent(
	ctx context.Context, store *file.Store, descriptor *v1.Descriptor,
) ([]byte, error) {
	reader, err := a.StoreFetch(ctx, store, descriptor)
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
