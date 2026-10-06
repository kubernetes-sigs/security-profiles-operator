//go:build apparmor

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

package apparmorprofile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	sec "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

var (
	errInvalidCRD            = errors.New(errInvalidCustomResourceType)
	errApparmorProfileExists = errors.New(errProfileExists)
)

func TestInstallProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                string
		sut                 aaProfileManager
		profile             profilebaseapi.StatusBaseUser
		previouslyInstalled bool
		wantResult          bool
		wantErr             error
	}{
		{
			name:    "invalid profile CRD",
			sut:     aaProfileManager{},
			profile: &sec.SeccompProfile{},
			wantErr: errInvalidCRD,
		},
		{
			// A policy is loaded under this name and the file at our managed
			// location does not carry our marker, so it belongs to the host.
			// This must hold for every generation: gating it on the first
			// generation let an attacker patch the spec once to get past it.
			name: "refuses to overwrite a host profile",
			sut: aaProfileManager{
				loadProfile:        func(_ logr.Logger, _, _ string, _ bool) (bool, error) { return false, nil },
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return true },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile: &apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{
				Generation: 1,
			}},
			wantErr: errApparmorProfileExists,
		},
		{
			name: "refuses to overwrite a host profile on later generations",
			sut: aaProfileManager{
				loadProfile:        func(_ logr.Logger, _, _ string, _ bool) (bool, error) { return false, nil },
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return true },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile: &apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{
				Generation: 7,
			}},
			wantErr: errApparmorProfileExists,
		},
		{
			// The legitimate update path: we installed this profile, so the
			// file carries our marker and reloading it is allowed.
			name: "updates a profile we installed",
			sut: aaProfileManager{
				loadProfile:        func(_ logr.Logger, _, _ string, _ bool) (bool, error) { return true, nil },
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return true },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return true },
			},
			profile: &apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{
				Generation: 3,
			}},
			wantResult: true,
		},
		{
			// Upgrade path: the profile was installed before the marker existed,
			// so its file has none, but this node's own status proves it is
			// ours. Reinstalling stamps the marker.
			name: "adopts a profile this node already installed",
			sut: aaProfileManager{
				loadProfile:       func(_ logr.Logger, _, _ string, _ bool) (bool, error) { return true, nil },
				checkProfileExist: func(_ logr.Logger, _ string) bool { return true },
				profileManagedByUs: func(_ logr.Logger, _ string) bool {
					t.Error("ownership must not be consulted once the node status vouches for it")

					return false
				},
			},
			profile:             &apparmorprofileapi.AppArmorProfile{},
			previouslyInstalled: true,
			wantResult:          true,
		},
		{
			// A runtime loads its default profile without a file under
			// /etc/apparmor.d, so it must be refused even when nothing is
			// loaded yet and even when the node status vouches for it.
			name: "refuses a container runtime default profile",
			sut: aaProfileManager{
				loadProfile: func(_ logr.Logger, _, _ string, _ bool) (bool, error) {
					t.Error("a runtime default profile must never be loaded")

					return true, nil
				},
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return false },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile: &apparmorprofileapi.AppArmorProfile{ObjectMeta: metav1.ObjectMeta{
				Name: "cri-containerd.apparmor.d",
			}},
			previouslyInstalled: true,
			wantErr:             errors.New(errRuntimeProfile),
		},
		{
			name: "valid profile CRD",
			sut: aaProfileManager{
				loadProfile:        func(_ logr.Logger, _, _ string, _ bool) (bool, error) { return false, nil },
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return false },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile: &apparmorprofileapi.AppArmorProfile{},
		},
		{
			// The loader decides on the policy file it sees, so it needs the
			// evidence of the caller as well.
			name: "passes the ownership evidence to the loader",
			sut: aaProfileManager{
				loadProfile: func(_ logr.Logger, _, _ string, ownedByUs bool) (bool, error) {
					if !ownedByUs {
						return false, errors.New("ownership must be passed through")
					}

					return true, nil
				},
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return false },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile:             &apparmorprofileapi.AppArmorProfile{},
			previouslyInstalled: true,
			wantResult:          true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.sut.InstallProfile(tc.profile, tc.previouslyInstalled)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			} else {
				require.NoError(t, gotErr)
			}

			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

func TestRemoveProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		sut       aaProfileManager
		profile   profilebaseapi.StatusBaseUser
		ownedByUs bool
		wantErr   error
	}{
		{
			name:    "invalid profile CRD",
			sut:     aaProfileManager{},
			profile: &sec.SeccompProfile{},
			wantErr: errInvalidCRD,
		},
		{
			name: "valid profile CRD",
			sut: aaProfileManager{
				removeProfile: func(_ logr.Logger, _, _ string, ownedByUs bool) error {
					if ownedByUs {
						return errors.New("ownership must be passed through")
					}

					return nil
				},
			},
			profile: &apparmorprofileapi.AppArmorProfile{},
		},
		{
			name: "passes the ownership evidence through",
			sut: aaProfileManager{
				removeProfile: func(_ logr.Logger, _, _ string, ownedByUs bool) error {
					if !ownedByUs {
						return errors.New("ownership must be passed through")
					}

					return nil
				},
			},
			profile:   &apparmorprofileapi.AppArmorProfile{},
			ownedByUs: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotErr := tc.sut.RemoveProfile(tc.profile, tc.ownedByUs)
			if tc.wantErr == nil {
				require.NoError(t, gotErr)
			}

			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}
		})
	}
}

func TestNewAppArmorProfileManager(t *testing.T) {
	t.Parallel()

	pm := NewAppArmorProfileManager(log.Log)
	internal, ok := pm.(*aaProfileManager)

	require.True(t, ok)
	require.NotNil(t, internal.loadProfile)
	require.NotNil(t, internal.removeProfile)
	require.Equal(t, log.Log, internal.logger)
}

// TestFileManagedByUs covers what makes a profile ours. The previous definition
// was "a file exists at our managed location", but that location is
// /etc/apparmor.d, which is also where distributions keep their own profiles, so
// an AppArmorProfile named after one of them ("crun", "busybox", ...) was
// classified as ours and silently overwrote the host's profile.
func TestFileManagedByUs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		content string
		write   bool
		want    bool
	}{
		{
			name:    "a profile we installed",
			content: managedByMarker + "profile foo {\n}\n",
			write:   true,
			want:    true,
		},
		{
			name:    "a host profile that merely exists at our location",
			content: "abi <abi/4.0>,\nprofile crun {\n}\n",
			write:   true,
			want:    false,
		},
		{
			name:    "a file shorter than the marker",
			content: "#",
			write:   true,
			want:    false,
		},
		{
			name:    "the marker somewhere other than the first line",
			content: "profile foo {\n}\n" + managedByMarker,
			write:   true,
			want:    false,
		},
		{
			name:  "no file at all",
			write: false,
			want:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "profile")
			if tc.write {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))
			}

			require.Equal(t, tc.want, fileManagedByUs(path))
		})
	}
}

// TestFileHasContent covers the second ownership signal used on removal. A
// profile installed before the marker existed carries none, so without this a
// deletion would skip it and leave the policy loaded on the node for good.
func TestFileHasContent(t *testing.T) {
	t.Parallel()

	const policy = "profile foo {\n}\n"

	for _, tc := range []struct {
		name    string
		content string
		want    string
		write   bool
		expect  bool
	}{
		{
			name:    "a profile we wrote before the marker existed",
			content: policy,
			want:    policy,
			write:   true,
			expect:  true,
		},
		{
			name:    "a host profile of the same name",
			content: "abi <abi/4.0>,\nprofile foo {\n}\n",
			want:    policy,
			write:   true,
			expect:  false,
		},
		{
			// Otherwise a profile whose policy could not be generated would
			// match every unreadable or empty host file.
			name:    "an empty expectation never matches",
			content: "",
			want:    "",
			write:   true,
			expect:  false,
		},
		{
			name:   "no file at all",
			want:   policy,
			write:  false,
			expect: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "profile")
			if tc.write {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))
			}

			require.Equal(t, tc.expect, fileHasContent(path, tc.want))
		})
	}
}

// TestPolicyFileOwned covers what allows a removal to unload a profile. A
// missing policy file used to count as ours, so deleting an AppArmorProfile
// named after a profile a container runtime loaded without a file, such as
// docker-default, unloaded it from the host.
func TestPolicyFileOwned(t *testing.T) {
	t.Parallel()

	const policy = "profile foo {\n}\n"

	for _, tc := range []struct {
		name      string
		content   string
		write     bool
		ownedByUs bool
		want      bool
	}{
		{
			name:    "a file carrying our marker",
			content: managedByMarker + policy,
			write:   true,
			want:    true,
		},
		{
			name:    "a file we wrote before the marker existed",
			content: policy,
			write:   true,
			want:    true,
		},
		{
			name:      "a host profile, even when the node status vouches for it",
			content:   "abi <abi/4.0>,\nprofile foo {\n}\n",
			write:     true,
			ownedByUs: true,
			want:      false,
		},
		{
			name: "no file and no evidence we installed it",
			want: false,
		},
		{
			name:      "no file but installed by us on this node",
			ownedByUs: true,
			want:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "profile")
			if tc.write {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0o600))
			}

			require.Equal(t, tc.want, policyFileOwned(path, policy, tc.ownedByUs))
		})
	}
}

func TestIsRuntimeProfile(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]bool{
		"docker-default":            true,
		"cri-containerd.apparmor.d": true,
		"crio-default":              true,
		"crio-default-1.30.0":       true,
		"containers-default-0.60.0": true,
		"docker-default-custom":     false,
		"my-profile":                false,
		"containers-default":        false,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, want, isRuntimeProfile(name))
		})
	}
}

func TestProfileFilename(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]string{
		"profile":      "profile",
		"/usr/bin/foo": "usr.bin.foo",
		"a/b/":         "a.b",
		"..":           "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, want, profileFilename(name))
		})
	}
}

// fakePolicyLoader is a policyLoader which tracks the loaded policies.
type fakePolicyLoader struct {
	loaded  map[string]bool
	loads   int
	loadErr error
}

func (f *fakePolicyLoader) LoadPolicy(string) error {
	f.loads++
	if f.loadErr != nil {
		return f.loadErr
	}

	f.loaded["test"] = true

	return nil
}

func (f *fakePolicyLoader) PolicyLoaded(name string) (bool, error) {
	return f.loaded[name], nil
}

func TestLoadPolicyFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test")
	loader := &fakePolicyLoader{loaded: map[string]bool{}}

	updated, err := loadPolicyFile(logr.Discard(), loader, path, "test", "policy", false)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, 1, loader.loads)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, managedByMarker+"policy", string(content))

	// An unchanged and loaded policy is neither written nor loaded again.
	info, err := os.Stat(path)
	require.NoError(t, err)

	updated, err = loadPolicyFile(logr.Discard(), loader, path, "test", "policy", false)
	require.NoError(t, err)
	require.False(t, updated)
	require.Equal(t, 1, loader.loads)

	unchanged, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, os.SameFile(info, unchanged), "the file must not be replaced")

	// A policy which is not loaded anymore, for example after a reboot, is
	// loaded again.
	loader.loaded["test"] = false

	updated, err = loadPolicyFile(logr.Discard(), loader, path, "test", "policy", false)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, 2, loader.loads)

	// A changed policy is written and loaded.
	updated, err = loadPolicyFile(logr.Discard(), loader, path, "test", "changed", false)
	require.NoError(t, err)
	require.True(t, updated)
	require.Equal(t, 3, loader.loads)

	// A failed load restores the previous file.
	loader.loadErr = errors.New("parser failed")

	_, err = loadPolicyFile(logr.Discard(), loader, path, "test", "broken", false)
	require.ErrorContains(t, err, "parser failed")

	content, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, managedByMarker+"changed", string(content))
}

// TestLoadPolicyFileHostFile covers a policy file at our managed location
// which is not loaded into the kernel. The ownership check of InstallProfile
// only sees loaded policies, so a distribution or admin profile whose service
// is stopped, which is disabled or whose binary is absent used to be replaced,
// and the marker written into it let a later removal delete the host's file.
func TestLoadPolicyFileHostFile(t *testing.T) {
	t.Parallel()

	const (
		hostPolicy = "abi <abi/4.0>,\nprofile test {\n}\n"
		policy     = "profile test {\n}\n"
	)

	for _, tc := range []struct {
		name      string
		previous  string
		ownedByUs bool
		wantErr   error
		wantFile  string
	}{
		{
			name:     "an unmarked file of the host is left alone",
			previous: hostPolicy,
			wantErr:  errHostPolicyFile,
			wantFile: hostPolicy,
		},
		{
			name:      "the node status vouching for the profile allows the update",
			previous:  hostPolicy,
			ownedByUs: true,
			wantFile:  managedByMarker + policy,
		},
		{
			name:     "a file written before the marker existed gets the marker",
			previous: policy,
			wantFile: managedByMarker + policy,
		},
		{
			name:     "a file carrying our marker is updated",
			previous: managedByMarker + "profile test {\n  /etc/passwd r,\n}\n",
			wantFile: managedByMarker + policy,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "test")
			require.NoError(t, os.WriteFile(path, []byte(tc.previous), 0o600))

			loader := &fakePolicyLoader{loaded: map[string]bool{}}

			updated, err := loadPolicyFile(
				logr.Discard(),
				loader,
				path,
				"test",
				policy,
				tc.ownedByUs,
			)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.False(t, updated)
				require.Zero(t, loader.loads, "the policy of the host must not be loaded")
			} else {
				require.NoError(t, err)
				require.True(t, updated)
				require.Equal(t, 1, loader.loads)
			}

			content, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, tc.wantFile, string(content))
		})
	}
}
