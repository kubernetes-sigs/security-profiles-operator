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

package utiltest

import (
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

var errTest = errors.New("test")

func TestNewScheme(t *testing.T) {
	t.Parallel()

	scheme := NewScheme(t)

	for _, obj := range []client.Object{
		&corev1.Pod{},
		&configv1.APIServer{},
		&apparmorprofileapi.AppArmorProfile{},
		&profilebindingapi.ProfileBinding{},
		&profilerecordingapi.ProfileRecording{},
		&seccompprofileapi.SeccompProfile{},
		&secprofnodestatusapi.SecurityProfileNodeStatus{},
		&selinuxprofileapi.SelinuxProfile{},
		&selinuxprofileapi.RawSelinuxProfile{},
		&spodapi.SecurityProfilesOperatorDaemon{},
	} {
		gvks, _, err := scheme.ObjectKinds(obj)
		require.NoError(t, err)
		require.NotEmpty(t, gvks)
	}
}

func TestNewFakeClient(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "ns"}}
	key := client.ObjectKeyFromObject(pod)

	c := NewFakeClient(t, &interceptor.Funcs{}, pod)
	require.NoError(t, c.Get(t.Context(), key, &corev1.Pod{}))

	c = NewFakeClient(t, &interceptor.Funcs{
		Get: GetReturns(
			errTest,
			func(obj client.Object) { obj.SetLabels(map[string]string{"a": "b"}) },
		),
		Create:            CreateReturns(errTest),
		Delete:            DeleteReturns(errTest),
		Update:            UpdateReturns(errTest),
		SubResourceUpdate: SubResourceUpdateReturns(errTest),
	}, pod)

	got := &corev1.Pod{}
	require.ErrorIs(t, c.Get(t.Context(), key, got), errTest)
	require.Equal(t, map[string]string{"a": "b"}, got.Labels)
	require.ErrorIs(t, c.Create(t.Context(), &corev1.Pod{}), errTest)
	require.ErrorIs(t, c.Delete(t.Context(), pod), errTest)
	require.ErrorIs(t, c.Update(t.Context(), pod), errTest)
	require.ErrorIs(t, c.Status().Update(t.Context(), pod), errTest)
}

func TestRequireEvent(t *testing.T) {
	t.Parallel()

	rec := events.NewFakeRecorder(1)
	RequireNoEvent(t, rec)

	rec.Eventf(&corev1.Pod{}, nil, corev1.EventTypeNormal, "Reason", "Action", "message %d", 1)
	RequireEvent(t, rec, "Normal Reason message 1")
	RequireNoEvent(t, rec)
}
