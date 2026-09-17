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
	"fmt"
	"io"
	"os"
	"path/filepath"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/verify"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
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
	StorePush(context.Context, *file.Store, ocispec.Descriptor, io.Reader) error
	StoreFetch(context.Context, *file.Store, ocispec.Descriptor) (io.ReadCloser, error)
	StoreTag(context.Context, *file.Store, ocispec.Descriptor, string) error
	PackManifest(
		context.Context, content.Pusher, oras.PackManifestVersion, string, oras.PackManifestOptions,
	) (ocispec.Descriptor, error)
	ClientSecret(options.OIDCOptions) (string, error)
	LoadSigningMaterial(context.Context, *options.KeyOpts, *options.SignOptions) error
	SignCmd(
		context.Context, *options.RootOptions, options.KeyOpts, options.SignOptions, []string,
	) error
	VerifyCmd(context.Context, verify.VerifyCommand, string) error
	SignatureBundleExists(context.Context, string, *options.RegistryOptions) (bool, error)
	ResolveRepository(context.Context, *remote.Repository, string) (ocispec.Descriptor, error)
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
	return file.New(workingDir)
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

//nolint:gocritic // intentional for the mock
func (*defaultImpl) StorePush(
	ctx context.Context, store *file.Store, desc ocispec.Descriptor, content io.Reader,
) error {
	return store.Push(ctx, desc, content)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) StoreFetch(
	ctx context.Context, store *file.Store, desc ocispec.Descriptor,
) (io.ReadCloser, error) {
	return store.Fetch(ctx, desc)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) StoreTag(
	ctx context.Context, store *file.Store, desc ocispec.Descriptor, ref string,
) error {
	return store.Tag(ctx, desc, ref)
}

func (*defaultImpl) PackManifest(
	ctx context.Context, pusher content.Pusher,
	packManifestVersion oras.PackManifestVersion,
	artifactType string, opts oras.PackManifestOptions,
) (ocispec.Descriptor, error) {
	return oras.PackManifest(ctx, pusher, packManifestVersion, artifactType, opts)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) ClientSecret(o options.OIDCOptions) (string, error) {
	return o.ClientSecret()
}

// LoadSigningMaterial loads the trusted root and the signing config from the
// Sigstore TUF repository, like cosign sign does.
func (*defaultImpl) LoadSigningMaterial(
	ctx context.Context, ko *options.KeyOpts, o *options.SignOptions,
) error {
	return signcommon.LoadTrustedMaterialAndSigningConfig(
		ctx, ko, o.UseSigningConfig, o.SigningConfigPath,
		o.Rekor.URL, o.Fulcio.URL, o.OIDC.Issuer, o.TSAServerURL, o.TrustedRootPath, o.TlogUpload,
		o.NewBundleFormat, "", o.Key, o.IssueCertificate, o.Output, "",
		o.OutputCertificate, o.OutputPayload, o.OutputSignature, "",
	)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) SignCmd(
	ctx context.Context, ro *options.RootOptions, ko options.KeyOpts,
	signOpts options.SignOptions, imgs []string,
) error {
	return sign.SignCmd(ctx, ro, ko, signOpts, imgs)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) VerifyCmd(
	ctx context.Context, cmd verify.VerifyCommand, image string,
) error {
	return cmd.Exec(ctx, []string{image})
}

func (*defaultImpl) ResolveRepository(ctx context.Context,
	repo *remote.Repository, reference string,
) (ocispec.Descriptor, error) {
	return repo.Resolve(ctx, reference)
}

// SignatureBundleExists reports whether the image digest has a Sigstore
// bundle with the cosign signature predicate attached as OCI referrer.
func (*defaultImpl) SignatureBundleExists(
	ctx context.Context, image string, o *options.RegistryOptions,
) (bool, error) {
	digest, err := ggcrname.NewDigest(image, o.NameOptions()...)
	if err != nil {
		return false, fmt.Errorf("parse image digest: %w", err)
	}

	clientOpts, err := o.ClientOpts(ctx)
	if err != nil {
		return false, fmt.Errorf("get registry client options: %w", err)
	}

	index, err := ociremote.Referrers(digest, "", clientOpts...)
	if err != nil {
		return false, fmt.Errorf("list referrers: %w", err)
	}

	return hasSignatureBundle(index), nil
}

// hasSignatureBundle reports whether the referrers contain a Sigstore bundle
// with the cosign signature predicate. Bundles carry their predicate type as
// annotation, attestations like SLSA provenance or promotion records use
// other predicate types.
func hasSignatureBundle(index *ggcrv1.IndexManifest) bool {
	if index == nil {
		return false
	}

	for i := range index.Manifests {
		if index.Manifests[i].Annotations[ociremote.BundlePredicateType] == cosigntypes.CosignSignPredicateType {
			return true
		}
	}

	return false
}
