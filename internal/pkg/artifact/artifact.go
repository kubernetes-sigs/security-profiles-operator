/*
Copyright 2023 The Kubernetes Authors.

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
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

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

	content []byte
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

// Push a profile to a remote location.
func (a *Artifact) Push(
	files map[*v1.Platform]string,
	to, username, password string,
	annotations map[string]string,
) error {
	dir, err := a.MkdirTemp("", "push-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}

	defer func() {
		if err := a.RemoveAll(dir); err != nil {
			a.logger.Info("Unable to remove temp dir: " + err.Error())
		}
	}()

	a.logger.Info("Creating file store in: " + dir)

	store, err := a.FileNew(dir)
	if err != nil {
		return fmt.Errorf("create file store: %w", err)
	}

	defer func() {
		if err := a.FileClose(store); err != nil {
			a.logger.Info("Unable to close file store: " + err.Error())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	fileDescriptors := []v1.Descriptor{}

	a.logger.Info("Adding " + strconv.Itoa(len(files)) + " profiles")

	for platform, file := range files {
		a.logger.Info(
			"Adding profile " + file +
				" for platform " +
				platformToString(platform) +
				" to store",
		)

		absPath, err := a.FilepathAbs(file)
		if err != nil {
			return fmt.Errorf("get absolute file path: %w", err)
		}

		fileDescriptor, err := a.StoreAdd(
			ctx, store, profileName(platform), "", absPath,
		)
		if err != nil {
			return fmt.Errorf("add profile to store: %w", err)
		}

		maps.Copy(fileDescriptor.Annotations, annotations)

		fileDescriptor.Platform = platform
		fileDescriptors = append(fileDescriptors, fileDescriptor)
	}

	a.logger.Info("Packing files")

	manifestDescriptor, err := a.PackManifest(
		ctx,
		store,
		oras.PackManifestVersion1_1,
		oras.MediaTypeUnknownConfig,
		oras.PackManifestOptions{
			Layers: fileDescriptors,
		},
	)
	if err != nil {
		return fmt.Errorf("pack files: %w", err)
	}

	a.logger.Info("Verifying reference: " + to)

	parsedRef, err := a.ParseReference(to)
	if err != nil {
		return fmt.Errorf("parse reference: %w", err)
	}

	tag := parsedRef.Identifier()

	a.logger.Info("Using tag: " + tag)

	if err = a.StoreTag(ctx, store, manifestDescriptor, tag); err != nil {
		return fmt.Errorf("creating tag: %w", err)
	}

	ref := parsedRef.Context().Name()
	a.logger.Info("Creating repository for " + ref)

	repo, err := a.NewRepository(ref)
	if err != nil {
		return fmt.Errorf("create repository: %w", err)
	}

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

	a.logger.Info("Copying profile to repository")

	descriptor, err := a.Copy(ctx, store, tag, repo, tag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("copy to repository: %w", err)
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
	disableSignatureVerification bool,
) (*PullResult, error) {
	ctx, cancel := context.WithTimeout(c, defaultTimeout)
	defer cancel()

	// Retrieve the immutable image digest before doing any verification to
	// prevent a TOCTOU attack on the mutable tag of the base image, which
	// it might lead to a malicious based profile being injected between
	// verification and copying the content
	a.logger.Info("Resolving digest of image: " + from)
	from, repo, digest, err := a.imageWithDigest(ctx, from, username, password)
	if err != nil {
		return nil, fmt.Errorf("resolving digest for image %q: %w", from, err)
	}

	if !disableSignatureVerification {
		a.logger.Info("Verifying signature")

		const all = ".*"

		v := verify.VerifyCommand{
			CertVerifyOptions: options.CertVerifyOptions{
				CertIdentityRegexp:   all,
				CertOidcIssuerRegexp: all,
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
			a.logger.Info("Unable to remove temp dir: " + err.Error())
		}
	}()

	a.logger.Info("Creating file store in: " + dir)

	store, err := a.FileNew(dir)
	if err != nil {
		return nil, fmt.Errorf("create file store: %w", err)
	}

	defer func() {
		if err := a.FileClose(store); err != nil {
			a.logger.Info("Unable to close file store: " + err.Error())
		}
	}()

	sha := digest.String()
	a.logger.Info("Use image digest: %s", sha)
	a.logger.Info("Copying profile from repository")

	if _, err := a.Copy(
		ctx, repo, sha, store, sha, oras.DefaultCopyOptions,
	); err != nil {
		return nil, fmt.Errorf("copy from repository: %w", err)
	}

	a.logger.Info("Checking profile contents")

	// Allow a fallback to defaultProfileYAML if no platform is available.
	content := []byte{}

	for _, name := range []string{profileName(platform), defaultProfileYAML} {
		a.logger.Info("Trying to read profile: " + name)

		content, err = a.ReadFile(filepath.Join(dir, name))
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	profile, err := a.ReadProfile(content)
	if err != nil {
		return nil, errors.Join(ErrDecodeYAML, err)
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
	string, *remote.Repository, digest.Digest, error) {
	ref, err := a.ParseReference(image)
	if err != nil {
		return "", nil, "", fmt.Errorf("parsing ref for image %q: %w", image, err)
	}

	repo, err := a.NewRepository(ref.Name())
	if err != nil {
		return "", nil, "", fmt.Errorf("creating repository for %q: %w",
			ref.Context().Name(), err)
	}

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

	desc, err := a.ResolveRepository(ctx, repo, ref.Identifier())
	if err != nil {
		return "", nil, "",
			fmt.Errorf("resolving image identifier %q: %w", ref.Identifier(), err)
	}

	return fmt.Sprintf("%s@%s", ref.Name(),
		desc.Digest.String()), repo, desc.Digest, nil
}

// profileName returns the name for the profile based on the platform.
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

	name.WriteString(".yaml")

	return name.String()
}

// platformToString returns a string for the provided platform.
func platformToString(platform *v1.Platform) string {
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
