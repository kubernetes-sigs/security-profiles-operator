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
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile/seccompprofilefakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"
	errOops := errors.New("oops")

	supported := &seccompprofilefakes.FakeImpl{}
	supported.IsSupportedReturns(true)
	supported.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{}, nil)

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
				impl: supported,
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
			name: "ErrGetProfile",
			rec: &Reconciler{
				impl: supported,
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
			wantErr:    fmt.Errorf("%w: %w", common.ErrGetProfile, errOops),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.rec.Reconcile(t.Context(), tc.req)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

// Reconcile installs a profile which it finds on a node with seccomp.
func TestReconcileInstallsProfile(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())
	env.impl.IsSupportedReturns(true)

	res, err := env.rec.Reconcile(t.Context(), reconcile.Request{NamespacedName: testProfileKey})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)
	require.Len(t, env.saved, 1)
	require.Equal(t, secprofnodestatusapi.ProfileStateInstalled, env.nodeStatus(t).Status.Status)
}

// A node which installed a profile and lost seccomp since must not block the
// deletion of the profile with its finalizer.
func TestReconcileNotSupportedReleasesDeletedProfile(t *testing.T) {
	t.Parallel()

	env := newReconcileEnv(t, newTestProfile())
	env.impl.IsSupportedReturns(true)

	req := reconcile.Request{NamespacedName: testProfileKey}

	_, err := env.rec.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.NotNil(t, env.nodeStatus(t))

	env.impl.IsSupportedReturns(false)
	require.NoError(t, env.cli.Delete(t.Context(), newTestProfile()))

	res, err := env.rec.Reconcile(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{}, res)

	err = env.cli.Get(t.Context(), testProfileKey, &seccompprofileapi.SeccompProfile{})
	if !builtWithSeccomp {
		require.NoError(t, err, "a build without seccomp keeps the finalizer")

		return
	}

	require.True(t, kerrors.IsNotFound(err), "the profile is gone: %v", err)
	require.Nil(t, env.nodeStatus(t))
}

// A node without seccomp reports every profile once instead of on every
// reconcile and liveness probe, and again if the profile got created again.
func TestReconcileNotSupportedReportsProfileOnce(t *testing.T) {
	t.Parallel()

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "profile", Namespace: "ns", UID: "first"},
	}
	cli := fake.NewClientBuilder().
		WithScheme(utiltest.NewScheme(t)).
		WithObjects(profile).
		WithStatusSubresource(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
		Build()
	mock := &seccompprofilefakes.FakeImpl{}
	recorder := events.NewFakeRecorder(10)
	rec := &Reconciler{
		impl:     mock,
		client:   cli,
		log:      log.Log,
		record:   recorder,
		metrics:  metrics.New(),
		nodeName: "node",
	}
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "profile"}}
	wantEvent := "Warning SeccompNotSupportedOnNode node \"node\": seccomp not supported"

	for range 3 {
		res, err := rec.Reconcile(t.Context(), req)
		require.NoError(t, err)
		require.Equal(t, reconcile.Result{}, res)
	}

	utiltest.RequireEvent(t, recorder, wantEvent)
	utiltest.RequireNoEvent(t, recorder)
	require.Zero(t, mock.GetSPODCallCount(), "the profile must not be installed")

	// The node status tells that the node cannot install the profile, it is
	// created without the finalizer of the node.
	statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	require.NoError(t, cli.List(t.Context(), statuses))

	if builtWithSeccomp {
		require.Len(t, statuses.Items, 1)
		require.True(t, nodestatus.IsUnsupported(&statuses.Items[0]))
		require.Equal(t, secprofnodestatusapi.ProfileStateError, statuses.Items[0].Status.Status)
		require.Contains(t, statuses.Items[0].Status.Message, errSeccompNotSupported.Error())
	} else {
		require.Empty(t, statuses.Items, "a build without seccomp tells nothing about the node")
	}

	// A profile created again under the same name is reported again.
	require.NoError(t, cli.Delete(t.Context(), profile))
	_, err := rec.Reconcile(t.Context(), req)
	require.NoError(t, err)

	recreated := profile.DeepCopy()
	recreated.ResourceVersion = ""
	recreated.UID = "second"
	require.NoError(t, cli.Create(t.Context(), recreated))

	_, err = rec.Reconcile(t.Context(), req)
	require.NoError(t, err)
	utiltest.RequireEvent(t, recorder, wantEvent)
	utiltest.RequireNoEvent(t, recorder)
}

// Expected perms on file.
func TestSaveProfileOnDisk(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cases := []struct {
		name        string
		setup       func(*testing.T)
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
			setup: func(t *testing.T) {
				t.Helper()

				targetDir := path.Join(dir, "/test/nopermissions")
				require.NoError(t, os.MkdirAll(targetDir, dirPermissionMode))
				require.NoError(t, os.Chmod(targetDir, 0))
			},
			fileName:    path.Join(dir, "/test/nopermissions/filename.json"),
			contents:    "some content",
			fileCreated: false,
			// The name of the temporary file is not part of the error, so
			// that the node status does not change with every attempt.
			wantErr: "cannot save profile: creating temporary file: open " +
				dir + "/test/nopermissions/.tmp-*: permission denied",
			needsNonRoot: true,
		},
		{
			name: "NoPermissionToWriteDir",
			setup: func(t *testing.T) {
				t.Helper()

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
				tc.setup(t)
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
			name: "AppendProfile",
			want: path.Join(config.ProfilesRootPath(), "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "file.json"},
			},
		},
		{
			name: "BlockTraversalAtProfileName",
			want: path.Join(config.ProfilesRootPath(), "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "../../../../../file.json"},
			},
		},
		{
			name: "IgnoreNamespace",
			want: path.Join(config.ProfilesRootPath(), "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "../../../../../ns",
				},
			},
		},
		{
			name: "AppendExtension",
			want: path.Join(config.ProfilesRootPath(), "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "file"},
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
		prepare func(t *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile
		assert  func(*testing.T, []seccompprofileapi.Syscall, error)
	}{
		{
			name: "success no base profile",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				return &seccompprofileapi.SeccompProfile{}
			},
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, syscalls)
			},
		},
		{
			name: "success two local base profiles",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
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
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, syscalls, 1)
				require.Equal(t, []string{"first", "second", "third"}, syscalls[0].Names)
			},
		},
		{
			name: "success two remote base profiles",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
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
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, syscalls, 1)
				require.Equal(t, []string{"first", "second", "third"}, syscalls[0].Names)
			},
		},
		{
			name: "failure on wrong PullResultTypeSeccompProfile",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullResultTypeReturns(artifact.PullResultTypeSelinuxProfile)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
					},
				}
			},
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.ErrorIs(t, err, errInvalidBaseProfile)
			},
		},
		{
			name: "failure on Pull",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.PullReturns(nil, errTest)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: config.OCIProfilePrefix + "test",
					},
				}
			},
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errTest)
				require.NotErrorIs(t, err, errInvalidBaseProfile, "a failed pull is retried")
			},
		},
		{
			name: "failure max recursion",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
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
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.ErrorIs(t, err, errInvalidBaseProfile)
			},
		},
		{
			name: "failure on ClientGetProfile",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.ClientGetProfileReturns(nil, errTest)

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: "test",
					},
				}
			},
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

				require.ErrorIs(t, err, errTest)
				require.NotErrorIs(t, err, errInvalidBaseProfile, "an API error is retried")
			},
		},
		{
			name: "failure on missing local base profile",
			prepare: func(_ *testing.T, mock *seccompprofilefakes.FakeImpl) *seccompprofileapi.SeccompProfile {
				mock.ClientGetProfileReturns(nil, kerrors.NewNotFound(schema.GroupResource{}, "test"))

				return &seccompprofileapi.SeccompProfile{
					Spec: seccompprofileapi.SeccompProfileSpec{
						BaseProfileName: "test",
					},
				}
			},
			assert: func(t *testing.T, syscalls []seccompprofileapi.Syscall, err error) {
				t.Helper()

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

			sp := prepare(t, mock)

			sut, ok := NewController().(*Reconciler)
			require.True(t, ok)

			sut.impl = mock
			sut.metrics = metrics.New()
			sut.record = events.NewFakeRecorder(10)

			syscalls, _, err := resolveWithSPOD(t.Context(), sut, sp)
			assert(t, syscalls, err)
		})
	}
}

// resolveWithSPOD resolves the syscalls of the profile with the SPOD of the
// daemon cache, like buildProfileContent does.
func resolveWithSPOD(
	ctx context.Context,
	sut *Reconciler,
	sp *seccompprofileapi.SeccompProfile,
) ([]seccompprofileapi.Syscall, bool, error) {
	spod, err := sut.GetSPOD(ctx, sut.client, sut.namespace)
	if err != nil {
		return nil, false, fmt.Errorf("retrieving the SPOD configuration: %w", err)
	}

	return sut.resolveSyscallsForProfile(ctx, sp, spod, sp.Spec.Syscalls, logr.Discard(), 0)
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
		syscalls, archSpecific, err := resolveWithSPOD(t.Context(), sut, sp)
		require.NoError(t, err)
		require.True(t, archSpecific, "an OCI base profile is pulled for the node")
		require.Len(t, syscalls, 1)
		require.Equal(t, []string{"first", "second"}, syscalls[0].Names)
	}

	require.Equal(t, 1, mock.PullCallCount(), "later resolutions must use the cache")
	require.Equal(t, 3, mock.GetSPODCallCount(), "the pull settings are part of the cache key")

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

	// Other pull settings, like a stricter identity, pull the base profile
	// again instead of using the one pulled with the former settings.
	mock.GetSPODReturns(&spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{Security: spodapi.SPODSecurityConfig{
			AllowedIdentityRegexp: "^me$",
		}},
	}, nil)

	_, _, err := resolveWithSPOD(t.Context(), sut, sp)
	require.NoError(t, err)
	require.Equal(t, 2, mock.PullCallCount())
}
