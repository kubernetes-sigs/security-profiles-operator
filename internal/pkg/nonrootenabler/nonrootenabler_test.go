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

package nonrootenabler_test

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler/nonrootenablerfakes"
)

var errTest = errors.New("error")

func TestRun(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		prepare     func(*nonrootenablerfakes.FakeImpl)
		shouldError bool
	}{
		"success": {
			prepare:     func(*nonrootenablerfakes.FakeImpl) {},
			shouldError: false,
		},
		"success symlink exists": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.LstatReturnsOnCall(0, nil, errTest)
			},
			shouldError: false,
		},
		"failure on CopyDirContentsLocal": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.CopyDirContentsLocalReturns(errTest)
			},
			shouldError: true,
		},
		"failure on Lchown": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.LchownReturns(errTest)
			},
			shouldError: true,
		},
		"failure on Symlink": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.LstatReturnsOnCall(0, nil, os.ErrNotExist)
				mock.SymlinkReturns(errTest)
			},
			shouldError: true,
		},
		"failure on kubelet directory not mounted": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MountedReturns(false, nil)
			},
			shouldError: true,
		},
		"failure on Mounted": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MountedReturns(false, errTest)
			},
			shouldError: true,
		},
		"failure on Chmod": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.ChmodReturns(errTest)
			},
			shouldError: true,
		},
		"failure on MkdirAll with KubeletSeccompRootPath": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MkdirAllReturnsOnCall(0, errTest)
			},
			shouldError: true,
		},
		"failure on MkdirAll with OperatorRoot": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MkdirAllReturnsOnCall(1, errTest)
			},
			shouldError: true,
		},
		"failure on SaveKubeletConfig failure": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.SaveKubeletConfigReturns(errTest)
			},
			shouldError: true,
		},
		"success on SaveKubeletDir success": {
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.SaveKubeletConfigReturns(nil)
			},
			shouldError: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut := nonrootenabler.New()
			mock := &nonrootenablerfakes.FakeImpl{}
			mock.MountedReturns(true, nil)
			tc.prepare(mock)
			sut.SetImpl(mock)

			err := sut.Run(logr.Discard(), "", config.KubeletDir(), false)
			if tc.shouldError {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestRunKubeletDirNotMounted asserts that nothing gets written when the
// kubelet directory of the node is not a mount point from the host, because
// the writes would otherwise end up in the container filesystem or in another
// mounted directory, for example when the label points to a parent of it.
func TestRunKubeletDirNotMounted(t *testing.T) {
	t.Parallel()

	sut := nonrootenabler.New()
	mock := &nonrootenablerfakes.FakeImpl{}
	mock.MountedReturns(false, nil)
	sut.SetImpl(mock)

	require.ErrorIs(t,
		sut.Run(logr.Discard(), "", "/mnt/resource/kubelet", false),
		nonrootenabler.ErrKubeletDirNotMounted,
	)
	require.Equal(t, 1, mock.MountedCallCount())
	require.Equal(t, "/host/mnt/resource/kubelet", mock.MountedArgsForCall(0))
	require.Zero(t, mock.MkdirAllCallCount())
	require.Zero(t, mock.SymlinkCallCount())
	require.Zero(t, mock.CopyDirContentsLocalCallCount())
}

// TestRunWritesExpectedPaths asserts what Run actually does to the node, rather
// than only that it returned no error.
func TestRunWritesExpectedPaths(t *testing.T) {
	t.Parallel()

	sut := nonrootenabler.New()
	mock := &nonrootenablerfakes.FakeImpl{}
	mock.MountedReturns(true, nil)
	mock.LstatReturnsOnCall(0, nil, os.ErrNotExist)
	sut.SetImpl(mock)

	require.NoError(t, sut.Run(logr.Discard(), "", config.KubeletDir(), false))

	// The kubelet directory is the only host path mounted below the host
	// root, so it has to be checked before anything gets written there.
	wantKubeletDir := path.Join(config.HostRoot, config.KubeletDir())

	require.Equal(t, 1, mock.MountedCallCount())
	require.Equal(t, wantKubeletDir, mock.MountedArgsForCall(0))
	require.Equal(t, 1, mock.LstatCallCount())

	wantSeccompDir := path.Join(wantKubeletDir, config.SeccompProfilesFolder)

	require.Equal(t, 2, mock.MkdirAllCallCount())
	gotDir, gotPerm := mock.MkdirAllArgsForCall(0)
	require.Equal(t, wantSeccompDir, gotDir)
	require.Equal(t, os.FileMode(0o744), gotPerm)

	gotDir, gotPerm = mock.MkdirAllArgsForCall(1)
	require.Equal(t, config.OperatorRoot, gotDir)
	require.Equal(t, os.FileMode(0o744), gotPerm)

	require.Equal(t, 1, mock.SymlinkCallCount())
	oldname, newname := mock.SymlinkArgsForCall(0)
	require.Equal(t, config.OperatorRoot, oldname)
	require.Equal(t, path.Join(wantSeccompDir, config.OperatorProfilesFolder), newname)

	require.Equal(t, 1, mock.LchownCallCount())
	lchownPath, uid, gid := mock.LchownArgsForCall(0)
	require.Equal(t, config.OperatorRoot, lchownPath)
	require.Equal(t, config.UserRootless, uid)
	require.Equal(t, config.UserRootless, gid)

	require.Equal(t, 1, mock.CopyDirContentsLocalCallCount())
	src, dst := mock.CopyDirContentsLocalArgsForCall(0)
	require.Equal(t, config.DefaultSpoProfilePath, src)
	require.Equal(t, wantSeccompDir, dst)

	// The operator root has to end up traversable for the rootless user, which
	// is what the "failure on Chmod" case above exists for.
	require.Equal(t, 1, mock.ChmodCallCount())
	chmodPath, chmodPerm := mock.ChmodArgsForCall(0)
	require.Equal(t, config.OperatorRoot, chmodPath)
	require.Equal(t, os.FileMode(0o744), chmodPerm)
}
