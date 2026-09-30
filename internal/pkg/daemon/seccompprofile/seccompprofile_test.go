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

package seccompprofile

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"go.podman.io/common/pkg/seccomp"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile/seccompprofilefakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"
	errOops := errors.New("oops")

	cases := []struct {
		name       string
		rec        *Reconciler
		req        reconcile.Request
		wantResult reconcile.Result
		wantErr    error
	}{
		{
			name: "ProfileNotFound",
			rec: &Reconciler{
				client: utiltest.NewFakeClient(t, &interceptor.Funcs{
					Get: utiltest.GetReturns(kerrors.NewNotFound(schema.GroupResource{}, name)),
				}),
				log:     log.Log,
				metrics: metrics.New(),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "ErrGetProfileIfSeccompEnabled",
			rec: &Reconciler{
				client: utiltest.NewFakeClient(t, &interceptor.Funcs{
					Get: utiltest.GetReturns(errOops),
				}),
				record:  events.NewFakeRecorder(10),
				log:     log.Log,
				metrics: metrics.New(),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr: func() error {
				if seccomp.IsEnabled() {
					return fmt.Errorf("%w: %w", common.ErrGetProfile, errOops)
				}

				return nil
			}(),
		},
		{
			name: "GotProfile",
			rec: &Reconciler{
				client: utiltest.NewFakeClient(t, &interceptor.Funcs{
					Get:               utiltest.GetReturns(nil),
					Update:            utiltest.UpdateReturns(nil),
					SubResourceUpdate: utiltest.SubResourceUpdateReturns(nil),
				}),
				log:     log.Log,
				record:  events.NewFakeRecorder(10),
				save:    func(_ string, _ []byte) (bool, error) { return false, nil },
				metrics: metrics.New(),
			},
			req: reconcile.Request{
				NamespacedName: types.NamespacedName{Namespace: namespace, Name: name},
			},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.rec.Reconcile(t.Context(), tc.req)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}

			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

// Expected perms on file.
func TestSaveProfileOnDisk(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cases := []struct {
		name        string
		setup       func()
		fileName    string
		contents    string
		wantErr     string
		fileCreated bool
		// needsNonRoot marks cases that rely on the filesystem denying access.
		// Root bypasses permission bits, so only those cases are skipped rather
		// than the whole test, which used to make this a no-op in root
		// containers and leave the happy path untested there.
		needsNonRoot bool
	}{
		{
			name:        "CreateDirsAndWriteFile",
			fileName:    path.Join(dir, "/seccomp/operator/namespace/filename.json"),
			contents:    "some content",
			fileCreated: true,
		},
		{
			name: "NoPermissionToWriteFile",
			setup: func() {
				targetDir := path.Join(dir, "/test/nopermissions")
				require.NoError(t, os.MkdirAll(targetDir, dirPermissionMode))
				require.NoError(t, os.Chmod(targetDir, 0))
			},
			fileName:    path.Join(dir, "/test/nopermissions/filename.json"),
			contents:    "some content",
			fileCreated: false,
			wantErr: "cannot save profile: creating temporary file: open " +
				dir + "/test/nopermissions/.tmp-",
			needsNonRoot: true,
		},
		{
			name: "NoPermissionToWriteDir",
			setup: func() {
				targetDir := path.Join(dir, "/nopermissions")
				require.NoError(t, os.MkdirAll(targetDir, dirPermissionMode))
				require.NoError(t, os.Chmod(targetDir, 0))
			},
			fileName:     path.Join(dir, "/nopermissions/test/filename.json"),
			contents:     "some content",
			fileCreated:  false,
			wantErr:      "cannot create operator directory: mkdir " + dir + "/nopermissions/test: permission denied",
			needsNonRoot: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.needsNonRoot && os.Getuid() == 0 {
				t.Skip("root bypasses the permission bits this case relies on")
			}

			if tc.setup != nil {
				tc.setup()
			}

			_, gotErr := saveProfileOnDisk(tc.fileName, []byte(tc.contents))
			file, statErr := os.Stat(tc.fileName)
			gotFileCreated := file != nil

			if tc.wantErr == "" {
				require.NoError(t, gotErr)
				require.NoError(t, statErr)
			} else {
				require.ErrorContains(t, gotErr, tc.wantErr)
				require.Error(t, statErr)
			}

			require.Equal(t, tc.fileCreated, gotFileCreated, "was file created?")
		})
	}
}

func TestGetProfilePath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want string
		sp   *seccompprofileapi.SeccompProfile
	}{
		{
			name: "AppendNamespaceAndProfile",
			want: path.Join(config.ProfilesRootPath(), "config-namespace", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "config-namespace",
				},
			},
		},
		{
			name: "BlockTraversalAtProfileName",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "../../../../../file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtTargetName",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtSPNamespace",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "../../../../../ns",
				},
			},
		},
		{
			name: "AppendExtension",
			want: path.Join(config.ProfilesRootPath(), "config-namespace", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file",
					Namespace: "config-namespace",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.sp.GetProfilePath()
			require.Equal(t, tc.want, got)
		})
	}
}

var errTest = errors.New("test")

func TestResolveSyscallsForProfile(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile
		assert  func([]seccompprofileapi.Syscall, error)
	}{
		{
			name: "success no base profile",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				return &seccompprofileapi.SeccompProfile{}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.NoError(t, err)
				require.Empty(t, syscalls)
			},
		},
		{
			name: "success two local base profiles",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.ClientGetProfileReturnsOnCall(
					0,
					&seccompprofileapi.SeccompProfile{
						Spec: seccompprofileapi.SeccompProfileSpec{
							BaseProfileName: "test",
							Syscalls: []seccompprofileapi.Syscall{
								{Names: []string{"second"}, Action: seccompprofileapi.ActAllow},
							},
						},
					}, nil,
				)
				mock.ClientGetProfileReturnsOnCall(
					1,
					&seccompprofileapi.SeccompProfile{
						Spec: seccompprofileapi.SeccompProfileSpec{
							Syscalls: []seccompprofileapi.Syscall{
								{Names: []string{"third"}, Action: seccompprofileapi.ActAllow},
							},
						},
					}, nil,
				)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: "test",
						Syscalls: []seccompprofileapi.Syscall{
							{Names: []string{"first"}, Action: seccompprofileapi.ActAllow},
						},
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.NoError(t, err)
				require.Len(t, syscalls, 1)
				require.Equal(t, []string{"first", "second", "third"}, syscalls[0].Names)
			},
		},
		{
			name: "success two remote base profiles",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
				mock.PullResultSeccompProfileReturnsOnCall(0, &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test-1",
						Syscalls: []seccompprofileapi.Syscall{
							{Names: []string{"second"}, Action: seccompprofileapi.ActAllow},
						},
					},
				})
				mock.PullResultSeccompProfileReturnsOnCall(1, &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						Syscalls: []seccompprofileapi.Syscall{
							{Names: []string{"third"}, Action: seccompprofileapi.ActAllow},
						},
					},
				})

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test-0",
						Syscalls: []seccompprofileapi.Syscall{
							{Names: []string{"first"}, Action: seccompprofileapi.ActAllow},
						},
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.NoError(t, err)
				require.Len(t, syscalls, 1)
				require.Equal(t, []string{"first", "second", "third"}, syscalls[0].Names)
			},
		},
		{
			name: "failure on wrong PullResultTypeSeccompProfile",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullResultTypeReturns(artifact.PullResultTypeSelinuxProfile)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.ErrorIs(t, err, errInvalidBaseProfile)
			},
		},
		{
			name: "failure on Pull",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullReturns(nil, errTest)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, errTest)
				require.NotErrorIs(t, err, errInvalidBaseProfile, "a failed pull is retried")
			},
		},
		{
			name: "failure max recursion",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
				mock.PullResultSeccompProfileReturnsOnCall(0, &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
					},
				})

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
						Syscalls: []seccompprofileapi.Syscall{
							{Names: []string{"first"}},
						},
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.ErrorIs(t, err, errInvalidBaseProfile)
			},
		},
		{
			name: "failure on ClientGetProfile",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.ClientGetProfileReturns(nil, errTest)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: "test",
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.ErrorIs(t, err, errTest)
				require.NotErrorIs(t, err, errInvalidBaseProfile, "an API error is retried")
			},
		},
		{
			name: "failure on missing local base profile",
			prepare: func(mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.ClientGetProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "test"))

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: "test",
					},
				}
			},
			assert: func(syscalls []seccompprofileapi.Syscall, err error) {
				require.ErrorIs(t, err, errInvalidBaseProfile)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &seccompprofilefakes.FakeImpl{}
			mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)

			sp := prepare(mock)

			sut, ok := NewController().(*Reconciler)
			require.True(t, ok)

			sut.impl = mock
			sut.metrics = metrics.New()
			sut.record = events.NewFakeRecorder(10)

			syscalls, _, err := sut.resolveSyscallsForProfile(
				t.Context(), sp, sp.Spec.Syscalls, logr.Discard(), 0,
			)
			assert(syscalls, err)
		})
	}
}

// TestResolveSyscallsForProfileBaseProfileCache verifies that a remote base
// profile is pulled once, anonymously and with the runtime size limit, and
// that later resolutions of the same reference use the cache.
func TestResolveSyscallsForProfileBaseProfileCache(t *testing.T) {
	t.Parallel()

	mock := &seccompprofilefakes.FakeImpl{}
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)
	mock.PullResultTypeReturns(artifact.PullResultTypeSeccompProfile)
	mock.PullResultSeccompProfileReturns(&seccompprofileapi.SeccompProfile{
		Spec: seccompprofileapi.SeccompProfileSpec{
			Syscalls: []seccompprofileapi.Syscall{
				{Names: []string{"second"}, Action: seccompprofileapi.ActAllow},
			},
		},
	})

	sut, ok := NewController().(*Reconciler)
	require.True(t, ok)

	sut.impl = mock
	sut.metrics = metrics.New()
	sut.record = events.NewFakeRecorder(10)
	sut.namespace = "operator-ns"

	sp := &seccompprofileapi.SeccompProfile{
		Spec: seccompprofileapi.SeccompProfileSpec{
			BaseProfileName: config.OCIProfilePrefix + "registry/base:v1",
			Syscalls: []seccompprofileapi.Syscall{
				{Names: []string{"first"}, Action: seccompprofileapi.ActAllow},
			},
		},
	}

	for range 3 {
		syscalls, archSpecific, err := sut.resolveSyscallsForProfile(
			t.Context(), sp, sp.Spec.Syscalls, logr.Discard(), 0,
		)
		require.NoError(t, err)
		require.True(t, archSpecific, "an OCI base profile is pulled for the node")
		require.Len(t, syscalls, 1)
		require.Equal(t, []string{"first", "second"}, syscalls[0].Names)
	}

	require.Equal(t, 1, mock.PullCallCount(), "later resolutions must use the cache")
	require.Equal(t, 1, mock.GetSPODCallCount())

	_, _, namespace := mock.GetSPODArgsForCall(0)
	require.Equal(t, "operator-ns", namespace, "the SPOD is read from the operator namespace")

	_, _, from, username, password, platform, opts := mock.PullArgsForCall(0)
	require.Equal(t, "registry/base:v1", from)
	require.Empty(t, username)
	require.Empty(t, password)
	require.NotNil(t, platform)
	require.Equal(t, artifact.MaxRuntimeProfileSize, opts.MaxBlobSize)
	require.False(t, opts.DisableSignatureVerification)
	require.Equal(t, allowedAllRegexp, opts.AllowedIdentityRegexp)
	require.Equal(t, allowedAllRegexp, opts.AllowedOidcIssuerRegexp)
}

// TestRemoveStaleTempFiles asserts that the leftovers of interrupted profile
// writes get removed from the directories of the namespaces as well.
func TestRemoveStaleTempFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nsDir := path.Join(root, "default")
	require.NoError(t, os.Mkdir(nsDir, 0o700))

	old := time.Now().Add(-time.Hour)
	stale := path.Join(nsDir, ".tmp-"+rand.Text())
	require.NoError(t, os.WriteFile(stale, []byte("{}"), 0o600))
	require.NoError(t, os.Chtimes(stale, old, old))

	profile := path.Join(nsDir, "profile.json")
	require.NoError(t, os.WriteFile(profile, []byte("{}"), 0o600))
	require.NoError(t, os.Chtimes(profile, old, old))

	removeStaleTempFiles(logr.Discard(), root)

	require.NoFileExists(t, stale)
	require.FileExists(t, profile)
}
