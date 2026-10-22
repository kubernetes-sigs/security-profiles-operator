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

package nonrootenabler

import (
	"errors"
	"path"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler/nonrootenablerfakes"
)

// fakeProfileManager is an AppArmor profile manager which only reports
// whether AppArmor is enabled.
type fakeProfileManager struct {
	enabled bool
}

func (m *fakeProfileManager) Enabled() bool {
	return m.enabled
}

func (*fakeProfileManager) KnownUnsupported() bool {
	return false
}

func (*fakeProfileManager) InstallProfile(profilebaseapi.StatusBaseUser, bool) (bool, error) {
	return false, nil
}

func (*fakeProfileManager) RemoveProfile(profilebaseapi.StatusBaseUser, bool) (bool, error) {
	return false, nil
}

func (*fakeProfileManager) ProfileInstalled(profilebaseapi.StatusBaseUser) (bool, error) {
	return false, nil
}

func TestInstallApparmorProfiles(t *testing.T) {
	t.Parallel()

	errInstall := errors.New("install failed")

	for _, tc := range []struct {
		name         string
		enabled      bool
		installErr   error
		wantInstalls []string
		wantErr      error
	}{
		{
			name:    "AppArmor disabled",
			enabled: false,
		},
		{
			name:    "installs every profile",
			enabled: true,
			wantInstalls: []string{
				path.Join(config.DefaultSpoProfilePath, config.SpoApparmorProfile),
				path.Join(config.DefaultSpoProfilePath, config.BpfRecorderApparmorProfile),
			},
		},
		{
			name:       "stops at the first error",
			enabled:    true,
			installErr: errInstall,
			wantInstalls: []string{
				path.Join(config.DefaultSpoProfilePath, config.SpoApparmorProfile),
			},
			wantErr: errInstall,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &nonrootenablerfakes.FakeImpl{}
			mock.InstallApparmorReturns(tc.installErr)

			manager := &fakeProfileManager{enabled: tc.enabled}
			sut := &NonRootEnabler{mock}

			err := sut.installApparmorProfiles(logr.Discard(), manager)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, len(tc.wantInstalls), mock.InstallApparmorCallCount())

			for i, want := range tc.wantInstalls {
				gotManager, gotProfile := mock.InstallApparmorArgsForCall(i)
				require.Same(t, manager, gotManager)
				require.Equal(t, want, gotProfile)
			}
		})
	}
}

func TestRelocateProfilesRoot(t *testing.T) {
	t.Parallel()

	newFs := func() *apparmorprofileapi.AppArmorFsRules {
		return &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths: []string{
				"/etc/apparmor.d/",
				"/var/lib/kubelet/seccomp/operator/",
			},
			WriteOnlyPaths: []string{"/var/lib/kubelet/seccomp/operator/file"},
			ReadWritePaths: []string{
				"/var/lib/kubelet/seccomp/operator/**",
				"/var/lib/kubelet/seccomp/operator-other/**",
				"/var/lib/kubelet/seccomp/**",
			},
		}
	}

	for _, tc := range []struct {
		name         string
		fs           *apparmorprofileapi.AppArmorFsRules
		profilesRoot string
		want         *apparmorprofileapi.AppArmorFsRules
	}{
		{
			name:         "default kubelet directory",
			fs:           newFs(),
			profilesRoot: "/var/lib/kubelet/seccomp/operator",
			want:         newFs(),
		},
		{
			name:         "custom kubelet directory",
			fs:           newFs(),
			profilesRoot: "/var/lib/k0s/kubelet/seccomp/operator",
			want: &apparmorprofileapi.AppArmorFsRules{
				ReadOnlyPaths: []string{
					"/etc/apparmor.d/",
					"/var/lib/k0s/kubelet/seccomp/operator/",
				},
				WriteOnlyPaths: []string{"/var/lib/k0s/kubelet/seccomp/operator/file"},
				ReadWritePaths: []string{
					"/var/lib/k0s/kubelet/seccomp/operator/**",
					"/var/lib/kubelet/seccomp/operator-other/**",
					"/var/lib/kubelet/seccomp/**",
				},
			},
		},
		{
			name:         "no file system rules",
			profilesRoot: "/var/lib/k0s/kubelet/seccomp/operator",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profile := &apparmorprofileapi.AppArmorProfile{}
			profile.Spec.Abstract.Filesystem = tc.fs

			relocateProfilesRoot(profile, tc.profilesRoot)
			require.Equal(t, tc.want, profile.Spec.Abstract.Filesystem)
		})
	}
}

// TestDaemonProfilesRoot cannot run in parallel, because the environment
// variables are global.
func TestDaemonProfilesRoot(t *testing.T) {
	for _, tc := range []struct {
		name, kubeletDir, want string
	}{
		{
			name: "default kubelet directory",
			want: "/var/lib/kubelet/seccomp/operator",
		},
		{
			name:       "custom kubelet directory",
			kubeletDir: "/var/lib/k0s/kubelet",
			want:       "/var/lib/k0s/kubelet/seccomp/operator",
		},
		{
			name:       "trailing slash",
			kubeletDir: "/var/lib/k0s/kubelet/",
			want:       "/var/lib/k0s/kubelet/seccomp/operator",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.KubeletDirEnvKey, tc.kubeletDir)

			require.Equal(t, tc.want, daemonProfilesRoot())
		})
	}
}
