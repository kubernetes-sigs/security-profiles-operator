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
	"errors"
	"io"
	"os"
	"path/filepath"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	ParseReference(string, ...ggcrname.Option) (ggcrname.Reference, error)
	MkdirTemp(string, string) (string, error)
	RemoveAll(string) error
	FileNew(string) (*file.Store, error)
	FileClose(*file.Store) error
	FilepathAbs(string) (string, error)
	NewRepository(string) (*remote.Repository, error)
	Copy(
		context.Context,
		oras.ReadOnlyTarget,
		string,
		oras.Target,
		string,
		oras.CopyOptions,
	) (ocispec.Descriptor, error)
	ReadFile(string) ([]byte, error)
	ReadProfile([]byte) (client.Object, error)
	StoreAdd(context.Context, *file.Store, string, string, string) (ocispec.Descriptor, error)
	StorePush(context.Context, *file.Store, *ocispec.Descriptor, io.Reader) error
	StoreFetch(context.Context, *file.Store, *ocispec.Descriptor) (io.ReadCloser, error)
	StoreTag(context.Context, *file.Store, *ocispec.Descriptor, string) error
	PackManifest(
		context.Context, content.Pusher, oras.PackManifestVersion, string, oras.PackManifestOptions,
	) (ocispec.Descriptor, error)
	ResolveRepository(context.Context, *remote.Repository, string) (ocispec.Descriptor, error)
	RepositoryPush(context.Context, *remote.Repository, *ocispec.Descriptor, io.Reader) error
	FetchAll(context.Context, *remote.Repository, *ocispec.Descriptor) ([]byte, error)
	FetchReference(
		context.Context, *remote.Repository, string, int64,
	) (ocispec.Descriptor, []byte, error)
	Referrers(
		context.Context,
		*remote.Repository,
		*ocispec.Descriptor,
	) ([]ocispec.Descriptor, error)
	SigningConfig(context.Context) (*root.SigningConfig, error)
	TrustedMaterial(context.Context, string, bool) (root.TrustedMaterial, error)
	IDToken(context.Context, string) (string, error)
	SignBundle(context.Context, sign.Content, *sign.BundleOptions) (*protobundle.Bundle, error)
	VerifyEntity(
		verify.SignedEntity,
		root.TrustedMaterial,
		[]verify.VerifierOption,
		verify.ArtifactPolicyOption,
		*verify.CertificateIdentity,
	) error
}

func (*defaultImpl) ParseReference(s string, opts ...ggcrname.Option) (ggcrname.Reference, error) {
	return ggcrname.ParseReference(s, opts...)
}

func (*defaultImpl) MkdirTemp(dir, pattern string) (string, error) {
	return os.MkdirTemp(dir, pattern)
}

func (*defaultImpl) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (*defaultImpl) FileNew(workingDir string) (*file.Store, error) {
	store, err := file.New(workingDir)
	if err != nil {
		return nil, err
	}

	// ORAS would otherwise extract layers annotated as directories without
	// any size limit.
	store.SkipUnpack = true

	return store, nil
}

func (*defaultImpl) FileClose(store *file.Store) error {
	return store.Close()
}

func (*defaultImpl) FilepathAbs(path string) (string, error) {
	return filepath.Abs(path)
}

func (*defaultImpl) NewRepository(reference string) (*remote.Repository, error) {
	return remote.NewRepository(reference)
}

func (*defaultImpl) Copy(
	ctx context.Context, src oras.ReadOnlyTarget, srcRef string,
	dst oras.Target, dstRef string, opts oras.CopyOptions,
) (ocispec.Descriptor, error) {
	return oras.Copy(ctx, src, srcRef, dst, dstRef, opts)
}

func (*defaultImpl) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (*defaultImpl) ReadProfile(raw []byte) (client.Object, error) {
	return ReadProfile(raw)
}

func (*defaultImpl) StoreAdd(
	ctx context.Context, store *file.Store, name, mediaType, path string,
) (ocispec.Descriptor, error) {
	return store.Add(ctx, name, mediaType, path)
}

func (*defaultImpl) StorePush(
	ctx context.Context, store *file.Store, desc *ocispec.Descriptor, r io.Reader,
) error {
	return store.Push(ctx, *desc, r)
}

func (*defaultImpl) StoreFetch(
	ctx context.Context, store *file.Store, desc *ocispec.Descriptor,
) (io.ReadCloser, error) {
	return store.Fetch(ctx, *desc)
}

func (*defaultImpl) StoreTag(
	ctx context.Context, store *file.Store, desc *ocispec.Descriptor, ref string,
) error {
	return store.Tag(ctx, *desc, ref)
}

func (*defaultImpl) PackManifest(
	ctx context.Context, pusher content.Pusher,
	packManifestVersion oras.PackManifestVersion,
	artifactType string, opts oras.PackManifestOptions,
) (ocispec.Descriptor, error) {
	return oras.PackManifest(ctx, pusher, packManifestVersion, artifactType, opts)
}

func (*defaultImpl) ResolveRepository(ctx context.Context,
	repo *remote.Repository, reference string,
) (ocispec.Descriptor, error) {
	return repo.Resolve(ctx, reference)
}

func (*defaultImpl) RepositoryPush(
	ctx context.Context, repo *remote.Repository, desc *ocispec.Descriptor, r io.Reader,
) error {
	return repo.Push(ctx, *desc, r)
}

func (*defaultImpl) FetchAll(
	ctx context.Context, repo *remote.Repository, desc *ocispec.Descriptor,
) ([]byte, error) {
	return content.FetchAll(ctx, repo, *desc)
}

// FetchReference fetches the manifest of the reference in one request, up to
// limit bytes. Unlike resolving a tag and fetching the digest, this reaches
// the same backend for both, which matters for registries like
// registry.k8s.io, which serve signature tags from another backend than
// manifest digests.
func (*defaultImpl) FetchReference(
	ctx context.Context, repo *remote.Repository, reference string, limit int64,
) (ocispec.Descriptor, []byte, error) {
	desc, rc, err := repo.FetchReference(ctx, reference)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	defer rc.Close()

	if err := blobSizeLimit(limit)(ctx, desc); err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	raw, err := content.ReadAll(rc, desc)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}

	return desc, raw, nil
}

// errEnoughReferrers stops the listing of referrers once maxSignatures have
// been collected.
var errEnoughReferrers = errors.New("enough referrers")

// Referrers lists the referrers of the subject, through the OCI referrers API
// or the referrers tag schema of registries without it. The listing stops
// after maxSignatures referrers, so that a registry cannot keep the pull busy.
func (*defaultImpl) Referrers(
	ctx context.Context, repo *remote.Repository, subject *ocispec.Descriptor,
) ([]ocispec.Descriptor, error) {
	var referrers []ocispec.Descriptor

	err := repo.Referrers(ctx, *subject, "", func(page []ocispec.Descriptor) error {
		referrers = append(referrers, page...)
		if len(referrers) >= maxSignatures {
			return errEnoughReferrers
		}

		return nil
	})
	if err != nil && !errors.Is(err, errEnoughReferrers) {
		return nil, err
	}

	return referrers, nil
}

func (*defaultImpl) SigningConfig(context.Context) (*root.SigningConfig, error) {
	opts, err := tufOptions()
	if err != nil {
		return nil, err
	}

	return root.FetchSigningConfigWithOptions(opts)
}

func (*defaultImpl) TrustedMaterial(
	_ context.Context, trustedRootPath string, offline bool,
) (root.TrustedMaterial, error) {
	if trustedRootPath != "" {
		trustedRoot, err := root.NewTrustedRootFromPath(trustedRootPath)
		if err != nil {
			return nil, err
		}

		return trustedRoot, nil
	}

	return tufTrustedRoot(offline)
}

func (*defaultImpl) IDToken(ctx context.Context, issuer string) (string, error) {
	return idToken(ctx, issuer)
}

// SignBundle signs the content with an ephemeral key into a Sigstore bundle.
func (*defaultImpl) SignBundle(
	ctx context.Context, data sign.Content, opts *sign.BundleOptions,
) (*protobundle.Bundle, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}

	bundleOpts := *opts
	bundleOpts.Context = ctx

	return sign.Bundle(data, keypair, bundleOpts)
}

// VerifyEntity verifies the signed entity against the trusted material. A
// nil identity verifies with the public key of the trusted material instead
// of a certificate.
func (*defaultImpl) VerifyEntity(
	entity verify.SignedEntity,
	material root.TrustedMaterial,
	opts []verify.VerifierOption,
	artifact verify.ArtifactPolicyOption,
	identity *verify.CertificateIdentity,
) error {
	verifier, err := verify.NewVerifier(material, opts...)
	if err != nil {
		return err
	}

	policy := verify.WithKey()
	if identity != nil {
		policy = verify.WithCertificateIdentity(*identity)
	}

	_, err = verifier.Verify(entity, verify.NewPolicy(artifact, policy))

	return err
}
