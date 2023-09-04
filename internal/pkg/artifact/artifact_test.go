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
	"runtime"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/name"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/registry/remote"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact/artifactfakes"
)

var errTest = errors.New("test")

func defaultDescriptor() ocispec.Descriptor {
	return ocispec.Descriptor{Annotations: map[string]string{}}
}

func TestPush(t *testing.T) {
	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.Nil(t, err)

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
			)
			assert(err)
		})
	}
}

func TestPull(t *testing.T) {
	testRef, err := name.ParseReference("docker.io/foo/bar:v1")
	require.Nil(t, err)

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
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
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
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
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
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.YamlUnmarshalReturnsOnCall(0, errTest)
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
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.YamlUnmarshalReturnsOnCall(0, errTest)
				mock.YamlUnmarshalReturnsOnCall(1, errTest)
			},
			assert: func(res *PullResult, err error) {
				require.NoError(t, err)
				require.NotNil(t, res)
				require.NotNil(t, res.Content())
				require.Equal(t, PullResultTypeApparmorProfile, res.Type())
				require.NotNil(t, res.ApparmorProfile())
			},
		},
		{
			name: "failure on all YAML decodes",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns([]byte{}, nil)
				mock.YamlUnmarshalReturns(errTest)
			},
			assert: func(res *PullResult, err error) {
				require.ErrorIs(t, err, ErrDecodeYAML)
				require.ErrorIs(t, err, errTest)
				require.Nil(t, res)
			},
		},
		{
			name: "failure on ReadFile",
			prepare: func(mock *artifactfakes.FakeImpl) {
				mock.NewRepositoryReturns(&remote.Repository{}, nil)
				mock.ParseReferenceReturns(testRef, nil)
				mock.ReadFileReturns(nil, errTest)
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
			name: "failure on FileNew",
			prepare: func(mock *artifactfakes.FakeImpl) {
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
			prepare(mock)

			sut := New(logr.Discard())
			sut.impl = mock

			res, err := sut.Pull(context.Background(), "", "foo", "bar", nil, false)
			assert(res, err)
		})
	}
}
