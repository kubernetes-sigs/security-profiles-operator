//go:build apparmor
// +build apparmor

/*
Copyright 2021 The Kubernetes Authors.

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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	sec "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

var errInvalidCRD = errors.New("invalid CRD kind")

func TestInstallProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		sut        aaProfileManager
		profile    profilebasev1alpha1.StatusBaseUser
		wantResult bool
		wantErr    error
	}{
		{
			name:    "invalid profile CRD",
			sut:     aaProfileManager{},
			profile: &sec.SeccompProfile{},
			wantErr: errInvalidCRD,
		},
		{
			name:    "valid profile CRD",
			sut:     aaProfileManager{loadProfile: func(_ logr.Logger, _, _ string) (bool, error) { return false, nil }},
			profile: &v1alpha1.AppArmorProfile{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.sut.InstallProfile(tc.profile)
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
		profile profilebasev1alpha1.StatusBaseUser
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
				removeProfile: func(_ logr.Logger, _ string) error { return nil },
			},
			profile: &v1alpha1.AppArmorProfile{},
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
