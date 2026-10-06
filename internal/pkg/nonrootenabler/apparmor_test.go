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

func (*fakeProfileManager) InstallProfile(profilebaseapi.StatusBaseUser, bool) (bool, error) {
	return false, nil
}

func (*fakeProfileManager) RemoveProfile(profilebaseapi.StatusBaseUser, bool) error {
	return nil
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
