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
				loadProfile:        func(_ logr.Logger, _, _ string) (bool, error) { return false, nil },
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
				loadProfile:        func(_ logr.Logger, _, _ string) (bool, error) { return false, nil },
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
				loadProfile:        func(_ logr.Logger, _, _ string) (bool, error) { return true, nil },
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
				loadProfile:       func(_ logr.Logger, _, _ string) (bool, error) { return true, nil },
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
			name: "valid profile CRD",
			sut: aaProfileManager{
				loadProfile:        func(_ logr.Logger, _, _ string) (bool, error) { return false, nil },
				checkProfileExist:  func(_ logr.Logger, _ string) bool { return false },
				profileManagedByUs: func(_ logr.Logger, _ string) bool { return false },
			},
			profile: &apparmorprofileapi.AppArmorProfile{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.sut.InstallProfile(tc.profile, tc.previouslyInstalled)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}

			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

func TestRemoveProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		sut     aaProfileManager
		profile profilebaseapi.StatusBaseUser
		wantErr error
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
				removeProfile: func(_ logr.Logger, _, _ string) error { return nil },
			},
			profile: &apparmorprofileapi.AppArmorProfile{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotErr := tc.sut.RemoveProfile(tc.profile)
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
