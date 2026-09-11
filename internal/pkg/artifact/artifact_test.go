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
	"io"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/security-profiles-merger/seccomp"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/artifactfakes"
)

var errTest = errors.New("test")

func defaultDescriptor() ocispec.Descriptor {
	return ocispec.Descriptor{Annotations: map[string]string{}}
}

func TestPushDisableSigning(t *testing.T) {
	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)

	t.Parallel()

	mock := &artifactfakes.FakeImpl{}
	mock.StoreAddReturns(defaultDescriptor(), nil)
	mock.ParseReferenceReturns(testRef, nil)
	mock.NewRepositoryReturns(&remote.Repository{}, nil)
	// Signing would fail if it ran at all.
	mock.ClientSecretReturns("", errTest)

	sut := New(logr.Discard())
	sut.impl = mock

	require.NoError(t, sut.Push(
		map[*ocispec.Platform]string{
			{OS: runtime.GOOS, Architecture: runtime.GOARCH}: "test",
		},
		"",
		"",
		"",
		nil,
		&PushOptions{DisableSigning: true},
	))
	require.Zero(t, mock.SignCmdCallCount())
}

func TestPush(t *testing.T) {
	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)

	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(mock *artifactfakes.FakeImpl)
		assert  func(error)
	}{
		{
			name: "success with failed cleanup",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.RemoveAllReturns(errTest)
				mock.FileCloseReturns(errTest)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "success",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
			},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "failure on SignCmd",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.SignCmdReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on ClientSecret",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ClientSecretReturns("", errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on Copy",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.CopyReturns(defaultDescriptor(), errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on NewRepository",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on StoreTag",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.StoreTagReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on ParseReferenceReturns",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.ParseReferenceReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on PackManifest",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.PackManifestReturns(defaultDescriptor(), errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on FilepathAbs",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), nil)
				mock.FilepathAbsReturns("", errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on StoreAdd",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.StoreAddReturns(defaultDescriptor(), errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on FileNew",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.FileNewReturns(nil, errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
		{
			name: "failure on MkdirTemp",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.MkdirTempReturns("", errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			prepare(mock)

			sut := New(logr.Discard())
			sut.impl = mock

			err := sut.Push(
				map[*ocispec.Platform]string{
					{
						OS:           runtime.GOOS,
						Architecture: runtime.GOARCH,
						OSVersion:    "1.2.3",
					}: "test",
				},
				"",
				"foo",
				"bar",
				map[string]string{"foo": "bar"},
				nil,
			)
			assert(err)
		})
	}
}

func TestPull(t *testing.T) {
	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)

	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(mock *artifactfakes.FakeImpl)
		assert  func(*PullResult, error)
	}{
		{
			name: "success with failed cleanup",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.ReadProfileReturns(&seccompprofileapi.SeccompProfile{}, nil)
				mock.RemoveAllReturns(errTest)
				mock.FileCloseReturns(errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.Content())
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.NotNil(t, res.SeccompProfile())
			},
		},
		{
			name: "success seccomp",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.ReadProfileReturns(&seccompprofileapi.SeccompProfile{}, nil)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.Content())
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.NotNil(t, res.SeccompProfile())
			},
		},
		{
			name: "success selinux",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.ReadProfileReturns(&selinuxprofileapi.SelinuxProfile{}, nil)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.Content())
				require.Equal(t, PullResultTypeSelinuxProfile, res.Type())
				require.NotNil(t, res.SelinuxProfile())
			},
		},
		{
			name: "success apparmor",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.ReadProfileReturns(&apparmorprofileapi.AppArmorProfile{}, nil)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.Content())
				require.Equal(t, PullResultTypeAppArmorProfile, res.Type())
				require.NotNil(t, res.ApparmorProfile())
			},
		},
		{
			name: "success runtime-spec seccomp profile",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte(rawSeccompJSON), nil)
				mock.ReadProfileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.JSONEq(t, rawSeccompJSON, string(res.Content()))
				require.Equal(t, "SeccompProfile", res.SeccompProfile().Kind)
				require.NotEmpty(t, res.SeccompProfile().GetName())
				require.Equal(t, seccompprofileapi.Action("SCMP_ACT_ERRNO"), res.SeccompProfile().Spec.DefaultAction)
				require.Len(t, res.SeccompProfile().Spec.Syscalls, 1)
			},
		},
		{
			name: "failure on all YAML decodes",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.ReadProfileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrDecodeYAML)
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "success on runtime format artifact",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				// No layer name, no title annotation and no file on disk.
				stubManifest(mock, &ocispec.Manifest{
					Config: ocispec.Descriptor{MediaType: MediaTypeSeccompProfile},
					Layers: []ocispec.Descriptor{testLayer("")},
				}, map[digest.Digest]string{testLayer("").Digest: rawSeccompJSON})
				mock.ReadFileReturns(nil, errTest)
				mock.ReadProfileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.JSONEq(t, rawSeccompJSON, string(res.Content()))
			},
		},
		{
			name: "success on runtime format artifact identified by artifactType",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				stubManifest(mock, &ocispec.Manifest{
					Config:       ocispec.Descriptor{MediaType: ocispec.MediaTypeEmptyJSON},
					ArtifactType: MediaTypeSeccompProfile,
					Layers:       []ocispec.Descriptor{testLayer("")},
				}, map[digest.Digest]string{testLayer("").Digest: rawSeccompJSON})
				mock.ReadFileReturns(nil, errTest)
				mock.ReadProfileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.JSONEq(t, rawSeccompJSON, string(res.Content()))
			},
		},
		{
			name: "failure on runtime format artifact with multiple layers",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				stubManifest(mock, &ocispec.Manifest{
					Config: ocispec.Descriptor{MediaType: MediaTypeSeccompProfile},
					Layers: []ocispec.Descriptor{testLayer("a"), testLayer("b")},
				}, nil)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrNoSingleLayer)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on undecodable runtime format artifact",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				stubManifest(mock, &ocispec.Manifest{
					Config: ocispec.Descriptor{MediaType: MediaTypeSeccompProfile},
					Layers: []ocispec.Descriptor{testLayer("")},
				}, map[digest.Digest]string{testLayer("").Digest: `{"syscalls":[]}`})
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrNoDefaultAction)
				require.ErrorContains(t, err, MediaTypeSeccompProfile)
				require.Nil(t, res)
			},
		},
		{
			name: "success on single layer with unknown name",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				stubManifest(mock, &ocispec.Manifest{
					Layers: []ocispec.Descriptor{testLayer("seccomp.json")},
				}, map[digest.Digest]string{testLayer("seccomp.json").Digest: rawSeccompJSON})
				mock.ReadFileReturns(nil, errTest)
				mock.ReadProfileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.Equal(t, PullResultTypeSeccompProfile, res.Type())
				require.JSONEq(t, rawSeccompJSON, string(res.Content()))
			},
		},
		{
			name: "failure on platform qualified single layer",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				stubManifest(mock, &ocispec.Manifest{
					Layers: []ocispec.Descriptor{testLayer("profile-linux-arm64.yaml")},
				}, nil)
				mock.ReadFileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrPlatformMismatch)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on single layer bound to another platform",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)

				layer := testLayer("seccomp.json")
				layer.Platform = &ocispec.Platform{OS: "linux", Architecture: "arm64"}

				stubManifest(mock, &ocispec.Manifest{
					Layers: []ocispec.Descriptor{layer},
				}, nil)
				mock.ReadFileReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrPlatformMismatch)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on ReadFile without single layer",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns(nil, errTest)
				stubManifest(mock, &ocispec.Manifest{
					Layers: []ocispec.Descriptor{
						testLayer("profile-linux-amd64.yaml"),
						testLayer("profile-linux-arm64.yaml"),
					},
				}, nil)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrNoSingleLayer)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on StoreFetch of the manifest",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.StoreFetchReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on unparsable manifest",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.StoreFetchStub = func(
					_ context.Context, _ *file.Store, _ ocispec.Descriptor,
				) (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader("not json")), nil
				}
			},
			assert: func(res *PullResult, err error) {
				require.ErrorContains(t, err, "unmarshal manifest")
				require.Nil(t, res)
			},
		},
		{
			name: "failure on StoreFetch of the single layer",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns(nil, errTest)

				manifest, err := json.Marshal(ocispec.Manifest{
					Layers: []ocispec.Descriptor{testLayer("seccomp.json")},
				})
				require.NoError(t, err)

				first := true
				mock.StoreFetchStub = func(
					_ context.Context, _ *file.Store, _ ocispec.Descriptor,
				) (io.ReadCloser, error) {
					if first {
						first = false

						return io.NopCloser(bytes.NewReader(manifest)), nil
					}

					return nil, errTest
				}
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on Copy",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.CopyReturns(defaultDescriptor(), errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on NewRepository",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ParseReferenceReturns(testRef, nil)
				mock.NewRepositoryReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on ParseReference",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ParseReferenceReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on ResolveRepository",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on FileNew",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.FileNewReturns(nil, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on MkdirTemp",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.MkdirTempReturns("", errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on VerifyCmd",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ResolveRepositoryReturns(ocispec.Descriptor{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.VerifyCmdReturns(errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			stubManifest(mock, &ocispec.Manifest{}, nil)
			prepare(mock)

			sut := New(logr.Discard())
			sut.impl = mock

			res, err := sut.Pull(t.Context(), "", "foo", "bar", nil, &PullOptions{})
			assert(res, err)
		})
	}
}

const rawSeccompJSON = `{"defaultAction":"SCMP_ACT_ERRNO","architectures":["SCMP_ARCH_X86_64"],` +
	`"syscalls":[{"names":["read","write"],"action":"SCMP_ACT_ALLOW"}]}`

// rawSeccompArgJSON uses an unsigned 64 bit argument value, which is valid in
// the runtime-spec but does not fit the CRD.
const rawSeccompArgJSON = `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["clone"],` +
	`"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":18446744073709551615,` +
	`"op":"SCMP_CMP_MASKED_EQ"}]}]}`

const profileCRDYAML = "apiVersion: security-profiles-operator.x-k8s.io/v1\nkind: SeccompProfile\n"

func TestPushMediaTypes(t *testing.T) {
	t.Parallel()

	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)

	platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}

	for _, tc := range []struct {
		name               string
		content            []byte
		readProfileErr     error
		wantLayerName      string
		wantLayerMediaType string
		wantLayerPlatform  *ocispec.Platform
		wantMediaType      string
		wantConfig         bool
	}{
		{
			name:               "runtime-spec seccomp profile",
			content:            []byte(rawSeccompJSON),
			readProfileErr:     errTest,
			wantLayerName:      defaultProfileJSON,
			wantLayerMediaType: layerMediaTypeJSON,
			wantLayerPlatform:  nil,
			wantMediaType:      MediaTypeSeccompProfile,
			wantConfig:         true,
		},
		{
			name:               "profile CRD",
			content:            []byte(profileCRDYAML),
			readProfileErr:     nil,
			wantLayerName:      "profile-linux-amd64.yaml",
			wantLayerMediaType: "",
			wantLayerPlatform:  platform,
			wantMediaType:      oras.MediaTypeUnknownConfig,
			wantConfig:         false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			mock.ReadFileReturns(tc.content, nil)
			mock.ReadProfileReturns(&seccompprofileapi.SeccompProfile{}, tc.readProfileErr)
			mock.StoreAddReturns(defaultDescriptor(), nil)
			mock.ParseReferenceReturns(testRef, nil)
			mock.NewRepositoryReturns(&remote.Repository{}, nil)

			sut := New(logr.Discard())
			sut.impl = mock

			err := sut.Push(map[*ocispec.Platform]string{platform: "profile"}, "", "", "", nil, nil)
			require.NoError(t, err)

			require.Equal(t, 1, mock.StoreAddCallCount())
			_, _, layerName, layerMediaType, _ := mock.StoreAddArgsForCall(0)
			require.Equal(t, tc.wantLayerName, layerName)
			require.Equal(t, tc.wantLayerMediaType, layerMediaType)

			require.Equal(t, 1, mock.PackManifestCallCount())
			_, _, _, mediaType, opts := mock.PackManifestArgsForCall(0)
			require.Equal(t, tc.wantMediaType, mediaType)
			require.Len(t, opts.Layers, 1)
			require.Equal(t, tc.wantLayerPlatform, opts.Layers[0].Platform)

			if !tc.wantConfig {
				require.Nil(t, opts.ConfigDescriptor)
				require.Equal(t, 0, mock.StorePushCallCount())

				return
			}

			// The config media type has to be set explicitly, ORAS would
			// otherwise default to the empty OCI config descriptor.
			require.NotNil(t, opts.ConfigDescriptor)
			require.Equal(t, tc.wantMediaType, opts.ConfigDescriptor.MediaType)

			require.Equal(t, 1, mock.StorePushCallCount())
			_, _, configDescriptor, _ := mock.StorePushArgsForCall(0)
			require.Equal(t, *opts.ConfigDescriptor, configDescriptor)
		})
	}
}

// TestPushManifest verifies the manifest ORAS produces for the options built
// by Push, because the config media type and the artifact type are set from
// different inputs.
func TestPushManifest(t *testing.T) {
	t.Parallel()

	layer := ocispec.Descriptor{
		MediaType: layerMediaTypeJSON,
		Digest:    digest.FromString(rawSeccompJSON),
		Size:      int64(len(rawSeccompJSON)),
		Annotations: map[string]string{
			ocispec.AnnotationTitle: defaultProfileJSON,
		},
	}
	config := ocispec.Descriptor{
		MediaType: MediaTypeSeccompProfile,
		Digest:    digest.FromBytes(emptyConfig),
		Size:      int64(len(emptyConfig)),
	}

	pusher := &testPusher{blobs: map[digest.Digest][]byte{}}

	descriptor, err := oras.PackManifest(
		t.Context(), pusher, oras.PackManifestVersion1_1, MediaTypeSeccompProfile,
		oras.PackManifestOptions{
			Layers:           []ocispec.Descriptor{layer},
			ConfigDescriptor: &config,
		},
	)
	require.NoError(t, err)

	manifest := ocispec.Manifest{}
	require.NoError(t, json.Unmarshal(pusher.blobs[descriptor.Digest], &manifest))

	// KEP-6061 identifies seccomp artifacts by the config media type, with
	// the artifact type as fallback for the empty OCI config descriptor.
	require.Equal(t, MediaTypeSeccompProfile, manifest.Config.MediaType)
	require.Equal(t, MediaTypeSeccompProfile, manifest.ArtifactType)
	require.NotEqual(t, ocispec.MediaTypeEmptyJSON, manifest.Config.MediaType)

	// KEP-6061 artifacts contain exactly one layer holding the raw profile.
	require.Len(t, manifest.Layers, 1)
	//nolint:testifylint // this compares a media type, not encoded JSON
	require.Equal(t, layerMediaTypeJSON, manifest.Layers[0].MediaType)
	require.Nil(t, manifest.Layers[0].Platform)
}

// testPusher is a content.Pusher which keeps all pushed blobs in memory.
type testPusher struct {
	blobs map[digest.Digest][]byte
}

//nolint:gocritic // the signature is defined by content.Pusher
func (t *testPusher) Push(
	_ context.Context, desc ocispec.Descriptor, content io.Reader,
) error {
	blob, err := io.ReadAll(content)
	if err != nil {
		return err
	}

	t.blobs[desc.Digest] = blob

	return nil
}

func TestPushRuntimeSpecSeccompProfileErrors(t *testing.T) {
	t.Parallel()

	amd64 := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := &ocispec.Platform{OS: "linux", Architecture: "arm64"}

	for _, tc := range []struct {
		name    string
		files   map[*ocispec.Platform]string
		prepare func(mock *artifactfakes.FakeImpl)
		wantErr error
	}{
		{
			name:  "multiple runtime-spec profiles",
			files: map[*ocispec.Platform]string{amd64: "raw-amd64", arm64: "raw-arm64"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ReadFileReturns([]byte(rawSeccompJSON), nil)
				mock.ReadProfileReturns(nil, errTest)
			},
			wantErr: ErrMultipleRuntimeSpecProfiles,
		},
		{
			name:  "mixed formats",
			files: map[*ocispec.Platform]string{amd64: "raw", arm64: "crd"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ReadFileStub = func(path string) ([]byte, error) {
					if strings.HasSuffix(path, "raw") {
						return []byte(rawSeccompJSON), nil
					}

					return []byte(profileCRDYAML), nil
				}
				mock.ReadProfileStub = func(content []byte) (client.Object, error) {
					if string(content) == rawSeccompJSON {
						return nil, errTest
					}

					return &seccompprofileapi.SeccompProfile{}, nil
				}
			},
			wantErr: ErrMixedProfileFormats,
		},
		{
			name:  "failure on ReadFile",
			files: map[*ocispec.Platform]string{amd64: "raw"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ReadFileReturns(nil, errTest)
			},
			wantErr: errTest,
		},
		{
			name:  "neither a profile CRD nor a runtime-spec profile",
			files: map[*ocispec.Platform]string{amd64: "moby"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				// The moby superset format used by the default profiles of
				// containers/common and docker.
				mock.ReadFileReturns([]byte(
					`{"defaultAction":"SCMP_ACT_ERRNO","archMap":[],"syscalls":[]}`,
				), nil)
				mock.ReadProfileReturns(nil, errTest)
			},
			wantErr: ErrDecodeYAML,
		},
		{
			name:  "garbage input",
			files: map[*ocispec.Platform]string{amd64: "garbage"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ReadFileReturns([]byte("not a profile at all"), nil)
				mock.ReadProfileReturns(nil, errTest)
			},
			wantErr: ErrDecodeYAML,
		},
		{
			name:  "failure on StorePush",
			files: map[*ocispec.Platform]string{amd64: "raw"},
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.ReadFileReturns([]byte(rawSeccompJSON), nil)
				mock.ReadProfileReturns(nil, errTest)
				mock.StorePushReturns(errTest)
			},
			wantErr: errTest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &artifactfakes.FakeImpl{}
			mock.FilepathAbsStub = func(path string) (string, error) { return path, nil }
			mock.StoreAddReturns(defaultDescriptor(), nil)
			tc.prepare(mock)

			sut := New(logr.Discard())
			sut.impl = mock

			err := sut.Push(tc.files, "", "", "", nil, nil)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestDecodeRuntimeSpecSeccompProfile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		content     string
		wantErr     error
		wantErrText string
	}{
		{name: "valid", content: rawSeccompJSON},
		{
			name: "valid with fields the CRD drops",
			content: `{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,` +
				`"flags":["SECCOMP_FILTER_FLAG_LOG"]}`,
		},
		{
			name:    "valid with values the CRD cannot hold",
			content: rawSeccompArgJSON,
		},
		{
			name:    "missing defaultAction",
			content: `{"syscalls":[]}`,
			wantErr: ErrNoDefaultAction,
		},
		{
			name:    "trailing data",
			content: rawSeccompJSON + `{"defaultAction":"SCMP_ACT_ALLOW"}`,
			wantErr: ErrTrailingData,
		},
		{
			name:        "unknown field",
			content:     `{"defaultAction":"SCMP_ACT_ERRNO","bogus":1}`,
			wantErrText: "unknown field",
		},
		{
			name:        "not JSON",
			content:     profileCRDYAML,
			wantErrText: "invalid character",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runtimeSpec, err := decodeRuntimeSpecSeccompProfile([]byte(tc.content))

			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, runtimeSpec)
			case tc.wantErrText != "":
				require.ErrorContains(t, err, tc.wantErrText)
				require.Nil(t, runtimeSpec)
			default:
				require.NoError(t, err)
				require.Equal(t,
					specs.LinuxSeccompAction("SCMP_ACT_ERRNO"),
					runtimeSpec.DefaultAction,
				)
			}
		})
	}
}

func TestRuntimeSpecSeccompProfileSpec(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		spec, err := runtimeSpecSeccompProfileSpec([]byte(rawSeccompJSON))
		require.NoError(t, err)
		require.Equal(t, seccompprofileapi.Action("SCMP_ACT_ERRNO"), spec.DefaultAction)
		require.Len(t, spec.Syscalls, 1)
	})

	t.Run("failure on decode", func(t *testing.T) {
		t.Parallel()

		spec, err := runtimeSpecSeccompProfileSpec([]byte(`{"syscalls":[]}`))
		require.ErrorIs(t, err, ErrNoDefaultAction)
		require.Nil(t, spec)
	})

	t.Run("failure on values the CRD cannot hold", func(t *testing.T) {
		t.Parallel()

		// The runtime-spec allows unsigned 64 bit argument values, the CRD
		// only signed ones. Push does not use this conversion, so such
		// profiles are still published in the runtime format.
		sut := New(logr.Discard())
		sut.impl = &artifactfakes.FakeImpl{ReadProfileStub: func([]byte) (client.Object, error) {
			return nil, errTest
		}}

		runtimeSpec, isRuntimeSpec, err := sut.runtimeSpecSeccompProfile(
			[]byte(rawSeccompArgJSON),
		)
		require.NoError(t, err)
		require.True(t, isRuntimeSpec)
		require.NotNil(t, runtimeSpec)

		spec, specErr := runtimeSpecSeccompProfileSpec([]byte(rawSeccompArgJSON))
		require.ErrorContains(t, specErr, "convert runtime-spec seccomp profile")
		require.Nil(t, spec)
	})
}

func TestNameFromReference(t *testing.T) {
	t.Parallel()

	for ref, want := range map[string]string{
		"registry.example.com/security/profiles/api-server-seccomp@sha256:abc": "api-server-seccomp",
		"localhost:5000/my_profile:v1":                                         "my-profile",
		"registry.k8s.io/security-profiles-operator/base/runc:v1.5.1":          "runc",
		"registry.example.com/UPPER/-Weird_Name-:tag":                          "weird-name",
		"registry.example.com/...":                                             "profile",
		"profile":                                                              "profile",
		"":                                                                     "profile",
	} {
		require.Equal(t, want, nameFromReference(ref), ref)
	}
}

// testLayer returns a layer descriptor with the provided title, which the
// ORAS file store uses as the file name, and no title at all if it is empty.
func testLayer(title string) ocispec.Descriptor {
	descriptor := ocispec.Descriptor{
		MediaType: layerMediaTypeJSON,
		Digest:    digest.FromString(title),
	}

	if title != "" {
		descriptor.Annotations = map[string]string{ocispec.AnnotationTitle: title}
	}

	return descriptor
}

// stubManifest makes StoreFetch return the manifest for every descriptor
// except the ones in blobs, which stand for the layers of the artifact.
func stubManifest(
	mock *artifactfakes.FakeImpl, manifest *ocispec.Manifest, blobs map[digest.Digest]string,
) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}

	mock.StoreFetchStub = func(
		_ context.Context, _ *file.Store, descriptor ocispec.Descriptor,
	) (io.ReadCloser, error) {
		if blob, ok := blobs[descriptor.Digest]; ok {
			return io.NopCloser(strings.NewReader(blob)), nil
		}

		return io.NopCloser(bytes.NewReader(raw)), nil
	}
}

// TestPushConfigBlob verifies that the config blob of a runtime format
// artifact ends up in the store, because it is only referenced by the
// manifest and would otherwise fail the copy to the registry.
func TestPushConfigBlob(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	store, err := file.New(dir)
	require.NoError(t, err)

	defer func() { require.NoError(t, store.Close()) }()

	sut := New(logr.Discard())

	config, err := sut.pushConfig(t.Context(), store, MediaTypeSeccompProfile)
	require.NoError(t, err)
	require.Equal(t, MediaTypeSeccompProfile, config.MediaType)

	reader, err := store.Fetch(t.Context(), config)
	require.NoError(t, err)

	defer func() { require.NoError(t, reader.Close()) }()

	blob, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, emptyConfig, blob)
}

func TestValidateRuntimeSpec(t *testing.T) {
	t.Parallel()

	manyNames := make([]string, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for i := range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		manyNames = append(manyNames, "syscall"+strconv.Itoa(i))
	}

	for _, tc := range []struct {
		name        string
		runtimeSpec *specs.LinuxSeccomp
		content     []byte
		skip        bool
		wantErr     error
		wantLogs    []string
	}{
		{
			name:        "valid profile",
			runtimeSpec: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
		},
		{
			name: "listener fields",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				ListenerPath:  "/var/run/agent.sock",
			},
			wantErr: seccomp.ErrListenerNotAllowed,
		},
		{
			name: "listener metadata only",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction:    specs.ActErrno,
				ListenerMetadata: "meta",
			},
			wantErr: seccomp.ErrListenerNotAllowed,
		},
		{
			name: "notify as default action",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActNotify,
			},
			wantErr: seccomp.ErrNotifyNotAllowed,
		},
		{
			name: "notify as syscall action",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"openat"}, Action: specs.ActNotify},
				},
			},
			wantErr: seccomp.ErrNotifyNotAllowed,
		},
		{
			name: "too many entries for one syscall",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls:      manyEntriesFor("openat"),
			},
			wantErr: seccomp.ErrTooManyEntries,
		},
		{
			name: "unknown architecture",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
			},
			wantErr: seccomp.ErrUnknownArch,
		},
		{
			name: "validation disabled logs instead of failing",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				ListenerPath:  "/var/run/agent.sock",
				Syscalls: []specs.LinuxSyscall{
					{Names: []string{"openat"}, Action: specs.ActNotify},
				},
			},
			skip:     true,
			wantLogs: []string{"artifact validation is disabled", "listenerPath", string(specs.ActNotify)},
		},
		{
			name:        "oversized profile",
			runtimeSpec: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
			content:     make([]byte, maxProfileSize+1),
			wantLogs:    []string{"larger than container runtimes accept"},
		},
		{
			name:        "profile at the size limit",
			runtimeSpec: &specs.LinuxSeccomp{DefaultAction: specs.ActErrno},
			content:     make([]byte, maxProfileSize),
		},
		{
			name: "many distinct syscalls are fine",
			runtimeSpec: &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{Names: manyNames, Action: specs.ActAllow},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			logs := &bytes.Buffer{}
			sut := New(funcr.New(func(_, args string) {
				logs.WriteString(args + "\n")
			}, funcr.Options{}))

			err := sut.validateRuntimeSpec(tc.runtimeSpec, tc.content, "profile.json", tc.skip)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, ErrRuntimeRestrictions)
				require.ErrorIs(t, err, tc.wantErr)
				require.Contains(t, err.Error(), "profile.json")
			} else {
				require.NoError(t, err)
			}

			if len(tc.wantLogs) == 0 {
				require.Empty(t, logs.String())

				return
			}

			for _, want := range tc.wantLogs {
				require.Contains(t, logs.String(), want)
			}
		})
	}
}

// manyEntriesFor returns more rule entries for the syscall than container
// runtimes accept.
func manyEntriesFor(syscall string) []specs.LinuxSyscall {
	entries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		entries = append(entries, specs.LinuxSyscall{
			Names:  []string{syscall},
			Action: specs.ActAllow,
		})
	}

	return entries
}

// Not parallel: it sets SOURCE_DATE_EPOCH, which the other push tests must
// not observe.
func TestPushCreatedAnnotation(t *testing.T) {
	push := func(t *testing.T, annotations map[string]string) (string, error) {
		t.Helper()

		mock := &artifactfakes.FakeImpl{}
		mock.ReadFileReturns([]byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), nil)
		mock.StoreAddReturns(defaultDescriptor(), nil)

		ref, err := name.ParseReference("docker.io/foo/bar:v1")
		require.NoError(t, err)
		mock.ParseReferenceReturns(ref, nil)
		mock.NewRepositoryReturns(&remote.Repository{}, nil)

		sut := New(logr.Discard())
		sut.impl = mock

		err = sut.Push(
			map[*ocispec.Platform]string{nil: "profile.json"},
			"", "", "", annotations, &PushOptions{DisableSigning: true},
		)
		if err != nil {
			return "", err
		}

		require.Equal(t, 1, mock.PackManifestCallCount())
		_, _, _, _, opts := mock.PackManifestArgsForCall(0)

		return opts.ManifestAnnotations[ocispec.AnnotationCreated], nil
	}

	// Build environments such as nix-shell export SOURCE_DATE_EPOCH; empty
	// counts as unset, so the default case is exercised regardless.
	t.Setenv(envSourceDateEpoch, "")

	created, err := push(t, nil)
	require.NoError(t, err)
	require.Equal(t, "1970-01-01T00:00:00Z", created,
		"default must be fixed for reproducible digests")

	created, err = push(t, map[string]string{ocispec.AnnotationCreated: "2026-09-11T07:00:00Z"})
	require.NoError(t, err)
	require.Equal(t, "2026-09-11T07:00:00Z", created, "an explicit annotation wins")

	t.Setenv("SOURCE_DATE_EPOCH", "1789110000")

	created, err = push(t, nil)
	require.NoError(t, err)
	require.Equal(t, "2026-09-11T07:00:00Z", created, "SOURCE_DATE_EPOCH is honored")

	t.Setenv("SOURCE_DATE_EPOCH", "yesterday")

	_, err = push(t, nil)
	require.ErrorIs(t, err, ErrInvalidSourceDateEpoch)
}

func TestPushPlainHTTP(t *testing.T) {
	t.Parallel()

	repo := &remote.Repository{}
	mock := &artifactfakes.FakeImpl{}
	mock.ReadFileReturns([]byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), nil)
	mock.StoreAddReturns(defaultDescriptor(), nil)

	ref, err := name.ParseReference("docker.io/foo/bar:v1")
	require.NoError(t, err)
	mock.ParseReferenceReturns(ref, nil)
	mock.NewRepositoryReturns(repo, nil)

	sut := New(logr.Discard())
	sut.impl = mock

	err = sut.Push(
		map[*ocispec.Platform]string{nil: "profile.json"},
		"", "", "", nil, &PushOptions{DisableSigning: true, PlainHTTP: true},
	)
	require.NoError(t, err)
	require.True(t, repo.PlainHTTP, "the repository must use plain HTTP when asked")
}
