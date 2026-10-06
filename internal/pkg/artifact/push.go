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
	"cmp"
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
)

// Push a profile to a remote location. Profiles without a platform are
// platform independent.
func (a *Artifact) Push(
	c context.Context,
	files map[*v1.Platform]string,
	to, username, password string,
	annotations map[string]string,
	opts *PushOptions,
) error {
	if opts == nil {
		opts = &PushOptions{}
	}

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

	// Packing works on the local store only.
	manifestDescriptor, err := a.packProfiles(
		c, store, files, annotations, opts.DisableArtifactValidation,
	)
	if err != nil {
		return err
	}

	var session *signingSession

	if opts.DisableSigning {
		a.logger.Info("Signing disabled, not signing the OCI artifact")
	} else {
		// A missing identity fails before anything gets pushed.
		session, err = a.prepareSigning(c, opts.OIDCDeviceFlow)
		if err != nil {
			return err
		}
	}

	// The timeout starts after the sign in, which may be interactive.
	ctx, cancel := context.WithTimeout(c, defaultTimeout)
	defer cancel()

	repo, pushed, err := a.copyToRepository(
		ctx, store, &manifestDescriptor, to, username, password, opts.PlainHTTP,
	)
	if err != nil {
		return err
	}

	if session == nil {
		return nil
	}

	if err := a.sign(ctx, repo, &pushed, session); err != nil {
		return &UnsignedError{Reference: digestReference(repo, pushed.Digest), Err: err}
	}

	return nil
}

// UnsignedError is returned by Push when the artifact got pushed but signing
// it failed, so that the caller can tell how to sign it after the fact.
type UnsignedError struct {
	// Reference is the pushed artifact by digest.
	Reference string

	// Err is the error of the signing.
	Err error
}

func (e *UnsignedError) Error() string {
	return fmt.Sprintf("pushed %s, but signing it failed: %v", e.Reference, e.Err)
}

func (e *UnsignedError) Unwrap() error {
	return e.Err
}

// digestReference returns the reference of the digest in the repository.
func digestReference(repo *remote.Repository, dgst digest.Digest) string {
	return fmt.Sprintf("%s/%s@%s", repo.Reference.Registry, repo.Reference.Repository, dgst)
}

// packProfiles adds the profile files to the store and packs them into a
// manifest, which it returns the descriptor of.
func (a *Artifact) packProfiles(
	ctx context.Context,
	store *file.Store,
	files map[*v1.Platform]string,
	annotations map[string]string,
	skipValidation bool,
) (v1.Descriptor, error) {
	a.logger.Info("Reading profiles", "count", len(files))

	entries, runtimeSpecProfiles, err := a.profileEntries(files, skipValidation)
	if err != nil {
		return v1.Descriptor{}, err
	}

	if runtimeSpecProfiles > 0 && runtimeSpecProfiles != len(files) {
		return v1.Descriptor{}, ErrMixedProfileFormats
	}

	if runtimeSpecProfiles > 1 {
		return v1.Descriptor{}, ErrMultipleRuntimeSpecProfiles
	}

	fileDescriptors := make([]v1.Descriptor, 0, len(entries))

	for _, entry := range entries {
		a.logger.Info("Adding profile to store",
			"file", entry.absPath,
			"platform", platformToString(entry.platform),
		)

		fileDescriptor, err := a.StoreAdd(
			ctx, store, entry.name, entry.layerMediaType, entry.absPath,
		)
		if err != nil {
			return v1.Descriptor{}, fmt.Errorf("add profile to store: %w", err)
		}

		fileDescriptor.Platform = entry.platform
		fileDescriptors = append(fileDescriptors, fileDescriptor)
	}

	manifestAnnotations, err := manifestAnnotations(annotations)
	if err != nil {
		return v1.Descriptor{}, err
	}

	mediaType := oras.MediaTypeUnknownConfig
	packOptions := oras.PackManifestOptions{
		Layers:              fileDescriptors,
		ManifestAnnotations: manifestAnnotations,
	}

	if runtimeSpecProfiles > 0 {
		mediaType = MediaTypeSeccompProfile

		configDescriptor, err := a.pushConfig(ctx, store, mediaType)
		if err != nil {
			return v1.Descriptor{}, fmt.Errorf("push config: %w", err)
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
		return v1.Descriptor{}, fmt.Errorf("pack files: %w", err)
	}

	return manifestDescriptor, nil
}

// copyToRepository tags the packed manifest and copies it to the repository
// of the reference. It returns the repository and the pushed manifest.
func (a *Artifact) copyToRepository(
	ctx context.Context,
	store *file.Store,
	manifestDescriptor *v1.Descriptor,
	to, username, password string,
	plainHTTP bool,
) (*remote.Repository, v1.Descriptor, error) {
	a.logger.Info("Verifying reference", "ref", to)

	parsedRef, err := a.ParseReference(to)
	if err != nil {
		return nil, v1.Descriptor{}, fmt.Errorf("parse reference: %w", err)
	}

	tag := parsedRef.Identifier()

	a.logger.Info("Using tag", "tag", tag)

	if err := a.StoreTag(ctx, store, manifestDescriptor, tag); err != nil {
		return nil, v1.Descriptor{}, fmt.Errorf("creating tag: %w", err)
	}

	ref := parsedRef.Context().Name()
	a.logger.Info("Creating repository", "ref", ref)

	repo, err := a.NewRepository(ref)
	if err != nil {
		return nil, v1.Descriptor{}, fmt.Errorf("create repository: %w", err)
	}

	repo.PlainHTTP = plainHTTP

	a.setRepoCredentials(repo, username, password)

	a.logger.Info("Copying profile to repository")

	descriptor, err := a.Copy(ctx, store, tag, repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return nil, v1.Descriptor{}, fmt.Errorf("copy to repository: %w", err)
	}

	a.logger.Info("Pushed artifact", "reference", fmt.Sprintf("%s@%s", ref, descriptor.Digest))

	return repo, descriptor, nil
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
// runtime-spec seccomp profiles, which are validated the way container
// runtimes validate them unless skipValidation is set.
func (a *Artifact) profileEntries(
	files map[*v1.Platform]string, skipValidation bool,
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

			err := a.validateRuntimeSpec(runtimeSpec, content, file, skipValidation)
			if err != nil {
				return nil, 0, err
			}

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

	// The files are a map, so the layer order would otherwise change from
	// push to push and with it the manifest digest of identical content.
	slices.SortFunc(entries, func(a, b profileEntry) int {
		return cmp.Compare(a.name, b.name)
	})

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

	if err := a.StorePush(ctx, store, &descriptor, bytes.NewReader(emptyConfig)); err != nil {
		return v1.Descriptor{}, fmt.Errorf("store config blob: %w", err)
	}

	return descriptor, nil
}

// manifestAnnotations returns the annotations of a pushed manifest: the ones
// of the caller plus org.opencontainers.image.created, which ORAS would
// otherwise stamp with the current time, giving identical content a
// different digest on every push.
func manifestAnnotations(annotations map[string]string) (map[string]string, error) {
	created, err := createdAnnotation(annotations)
	if err != nil {
		return nil, err
	}

	res := maps.Clone(annotations)
	if res == nil {
		res = map[string]string{}
	}

	res[v1.AnnotationCreated] = created

	return res, nil
}

// createdAnnotation returns the org.opencontainers.image.created value for
// a pushed manifest: the caller's annotation if set, otherwise
// SOURCE_DATE_EPOCH, otherwise a fixed epoch so that identical content
// always produces the same digest.
func createdAnnotation(annotations map[string]string) (string, error) {
	if created, ok := annotations[v1.AnnotationCreated]; ok {
		return created, nil
	}

	epoch, ok := os.LookupEnv(envSourceDateEpoch)
	if !ok || epoch == "" {
		return annotationCreatedDefault, nil
	}

	seconds, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidSourceDateEpoch, epoch)
	}

	return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
}
