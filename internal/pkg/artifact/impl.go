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
	"os"

	ggcrname "github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/verify"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"sigs.k8s.io/yaml"
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
	NewRepository(string) (*remote.Repository, error)
	Copy(context.Context, oras.ReadOnlyTarget, string, oras.Target, string, oras.CopyOptions) (ocispec.Descriptor, error)
	ReadFile(string) ([]byte, error)
	YamlUnmarshal([]byte, interface{}) error
	StoreAdd(context.Context, *file.Store, string, string, string) (ocispec.Descriptor, error)
	StoreTag(context.Context, *file.Store, ocispec.Descriptor, string) error
	Pack(context.Context, content.Pusher, string, []ocispec.Descriptor, oras.PackOptions) (ocispec.Descriptor, error)
	ClientSecret(options.OIDCOptions) (string, error)
	SignCmd(*options.RootOptions, options.KeyOpts, options.SignOptions, []string) error
	VerifyCmd(context.Context, verify.VerifyCommand, string) error
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

func (*defaultImpl) YamlUnmarshal(y []byte, o interface{}) error {
	return yaml.Unmarshal(y, o)
}

func (*defaultImpl) StoreAdd(
	ctx context.Context, store *file.Store, name, mediaType, path string,
) (ocispec.Descriptor, error) {
	return store.Add(ctx, name, mediaType, path)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) StoreTag(
	ctx context.Context, store *file.Store, desc ocispec.Descriptor, ref string,
) error {
	return store.Tag(ctx, desc, ref)
}

func (*defaultImpl) Pack(
	ctx context.Context, pusher content.Pusher, artifactType string,
	blobs []ocispec.Descriptor, opts oras.PackOptions,
) (ocispec.Descriptor, error) {
	return oras.Pack(ctx, pusher, artifactType, blobs, opts)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) ClientSecret(o options.OIDCOptions) (string, error) {
	return o.ClientSecret()
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) SignCmd(
	ro *options.RootOptions, ko options.KeyOpts,
	signOpts options.SignOptions, imgs []string,
) error {
	return sign.SignCmd(ro, ko, signOpts, imgs)
}

//nolint:gocritic // intentional for the mock
func (*defaultImpl) VerifyCmd(
	ctx context.Context, cmd verify.VerifyCommand, image string,
) error {
	return cmd.Exec(ctx, []string{image})
}
