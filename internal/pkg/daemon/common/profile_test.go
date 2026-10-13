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

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
		report, _ := reports.check(t.Context(), cl, key, &seccompprofileapi.SeccompProfile{})

		return report
	}

	require.True(t, shouldReport())
	require.False(t, shouldReport())

	require.NoError(t, cl.Delete(t.Context(), profile))
	require.False(t, shouldReport())

	_, loaded := reports.reported.Reported(key)
	require.False(t, loaded, "a deleted profile is forgotten")

	recreated := testProfile()
	recreated.UID = "second"
	require.NoError(t, cl.Create(t.Context(), recreated))
	require.True(t, shouldReport())
	require.False(t, shouldReport())
}

// A report is repeated only once it changed or got forgotten.
func TestReports(t *testing.T) {
	t.Parallel()

	key := client.ObjectKeyFromObject(testProfile())

	var reports Reports[string]

	_, reported := reports.Reported(key)
	require.False(t, reported)

	require.True(t, reports.ShouldReport(key, "first"))
	require.False(t, reports.ShouldReport(key, "first"))
	require.True(t, reports.ShouldReport(key, "second"))

	report, reported := reports.Reported(key)
	require.True(t, reported)
	require.Equal(t, "second", report)

	reports.Forget(key)
	require.True(t, reports.ShouldReport(key, "second"))
}

// An unsupported profile is reported as an event on the node and counted
// once, and only logged verbosely afterwards.
func TestUnsupportedReportsReport(t *testing.T) {
	t.Parallel()

	profile := testProfile()
	profile.UID = "uid"
	key := client.ObjectKeyFromObject(profile)
	cl := utiltest.NewFakeClient(t, &interceptor.Funcs{}, profile)
	recorder := events.NewFakeRecorder(10)
	reasons := []string{}
	reporter := ErrorReporter{
		Record:   recorder,
		IncError: func(reason string) { reasons = append(reasons, reason) },
	}

	var reports UnsupportedReports

	report := func() bool {
		return reports.Report(
			t.Context(), cl, key, &seccompprofileapi.SeccompProfile{}, logr.Discard(),
			reporter, "node", "NotSupported", errors.New("not supported"),
		)
	}

	for range 3 {
		require.False(t, report())
	}

	require.Equal(t, []string{"NotSupported"}, reasons)
	utiltest.RequireEvent(t, recorder, "Warning NotSupported not supported")
	utiltest.RequireNoEvent(t, recorder)

	// A profile which is gone is told to the caller.
	require.NoError(t, cl.Delete(t.Context(), profile))
	require.True(t, report())
	utiltest.RequireNoEvent(t, recorder)
}

// relatedRecorder records the objects of the events.
type relatedRecorder struct {
	regarding, related []runtime.Object
}

func (r *relatedRecorder) Eventf(
	regarding, related runtime.Object, _, _, _, _ string, _ ...any,
) {
	r.regarding = append(r.regarding, regarding)
	r.related = append(r.related, related)
}

// The event of an unsupported profile on the node refers to the profile, so
// that the events of the profiles can be told apart.
func TestUnsupportedReportsReportRelatesProfile(t *testing.T) {
	t.Parallel()

	profile := testProfile()
	profile.UID = "uid"
	cl := utiltest.NewFakeClient(t, &interceptor.Funcs{}, profile)
	recorder := &relatedRecorder{}

	var reports UnsupportedReports

	require.False(t, reports.Report(
		t.Context(), cl, client.ObjectKeyFromObject(profile), &seccompprofileapi.SeccompProfile{},
		logr.Discard(), ErrorReporter{Record: recorder}, "node", "NotSupported",
		errors.New("not supported"),
	))

	require.Len(t, recorder.regarding, 1)
	node, ok := recorder.regarding[0].(*corev1.Node)
	require.True(t, ok)
	require.Equal(t, "node", node.GetName())

	related, ok := recorder.related[0].(*seccompprofileapi.SeccompProfile)
	require.True(t, ok)
	require.Equal(t, profile.GetName(), related.GetName())
	require.Equal(t, profile.GetUID(), related.GetUID())
}
