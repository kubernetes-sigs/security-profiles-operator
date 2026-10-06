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

package common

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func TestReportError(t *testing.T) {
	t.Parallel()

	recorder := events.NewFakeRecorder(1)
	ErrorReporter{Record: recorder}.ReportError(
		testProfile(), "Reason", util.EventActionUpdate, errors.New("failed"),
	)

	require.Equal(t, "Warning Reason failed", <-recorder.Events)
}

func TestNewDeletionReasons(t *testing.T) {
	t.Parallel()

	require.Equal(t, DeletionReasons{
		CannotUpdateProfile: "CannotUpdate",
		CannotRemoveProfile: "CannotRemove",
		CannotUpdateStatus:  ReasonCannotUpdateStatus,
	}, NewDeletionReasons("CannotUpdate", "CannotRemove"))
}

func TestGetProfile(t *testing.T) {
	t.Parallel()

	errGet := errors.New("get failed")

	for _, tc := range []struct {
		name      string
		funcs     *interceptor.Funcs
		objs      []client.Object
		wantFound bool
		wantErr   error
	}{
		{
			name:      "found",
			objs:      []client.Object{testProfile()},
			wantFound: true,
		},
		{
			name: "gone",
		},
		{
			name:    "get error",
			funcs:   &interceptor.Funcs{Get: utiltest.GetReturns(errGet)},
			wantErr: ErrGetProfile,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			funcs := tc.funcs
			if funcs == nil {
				funcs = &interceptor.Funcs{}
			}

			cl := utiltest.NewFakeClient(t, funcs, tc.objs...)
			profile := &seccompprofileapi.SeccompProfile{}

			found, err := GetProfile(
				t.Context(), cl, client.ObjectKeyFromObject(testProfile()), profile,
			)
			require.Equal(t, tc.wantFound, found)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.ErrorIs(t, err, errGet)

				return
			}

			require.NoError(t, err)

			if found {
				require.Equal(t, testProfile().GetName(), profile.GetName())
			}
		})
	}
}

// A profile on a node which does not support it is reported once, and again
// if it got created again under the same name.
func TestUnsupportedReports(t *testing.T) {
	t.Parallel()

	profile := testProfile()
	profile.UID = "first"
	key := client.ObjectKeyFromObject(profile)
	cl := utiltest.NewFakeClient(t, &interceptor.Funcs{}, profile)

	var reports UnsupportedReports

	shouldReport := func() bool {
		return reports.ShouldReport(t.Context(), cl, key, &seccompprofileapi.SeccompProfile{})
	}

	require.True(t, shouldReport())
	require.False(t, shouldReport())

	require.NoError(t, cl.Delete(t.Context(), profile))
	require.False(t, shouldReport())

	_, loaded := reports.reported.Load(key)
	require.False(t, loaded, "a deleted profile is forgotten")

	recreated := testProfile()
	recreated.UID = "second"
	require.NoError(t, cl.Create(t.Context(), recreated))
	require.True(t, shouldReport())
	require.False(t, shouldReport())
}
