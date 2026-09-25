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

package recordingtracker

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

func TestRecordingStatusReportsKindAndRecorder(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		kind       profilerecordingapi.ProfileRecordingKind
		recorder   profilerecordingapi.ProfileRecorder
		wantReason common.ConditionReason
	}{
		"seccomp with bpf": {
			kind:       profilerecordingapi.ProfileRecordingKindSeccompProfile,
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			wantReason: common.ReasonAvailable,
		},
		"selinux with bpf": {
			kind:       profilerecordingapi.ProfileRecordingKindSelinuxProfile,
			recorder:   profilerecordingapi.ProfileRecorderBpf,
			wantReason: common.ReasonUnavailable,
		},
		"apparmor with logs": {
			kind:       profilerecordingapi.ProfileRecordingKindAppArmorProfile,
			recorder:   profilerecordingapi.ProfileRecorderLogs,
			wantReason: common.ReasonUnavailable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			recording := &profilerecordingapi.ProfileRecording{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "recording",
					Namespace:  "default",
					Generation: 3,
				},
				Spec: profilerecordingapi.ProfileRecordingSpec{
					Kind:     tc.kind,
					Recorder: tc.recorder,
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(newTestScheme(t)).
				WithStatusSubresource(recording).
				WithObjects(recording).
				Build()

			r := &recordingStatusReconciler{client: c, reader: c, log: logr.Discard()}

			_, err := r.Reconcile(t.Context(), reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(recording),
			})
			require.NoError(t, err)

			updated := &profilerecordingapi.ProfileRecording{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(recording), updated))

			ready := updated.Status.GetReadyCondition()
			require.Equal(t, string(tc.wantReason), ready.Reason)
			require.Equal(t, updated.Generation, ready.ObservedGeneration)
		})
	}
}
