/*
Copyright 2026 The Kubernetes Authors.

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

package nodestatus

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	apparmorapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestProfileStatusChanged(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		current profilebaseapi.StatusBaseUser
	}{
		{
			name: "SeccompProfile",
			current: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: seccompprofileapi.SeccompProfileStatus{
					StatusBase: profilebaseapi.StatusBase{Status: secprofnodestatusapi.ProfileStateInstalled},
				},
			},
		},
		{
			name: "SelinuxProfile",
			current: &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: selinuxprofileapi.SelinuxProfileStatus{
					StatusBase: profilebaseapi.StatusBase{Status: secprofnodestatusapi.ProfileStateInstalled},
				},
			},
		},
		{
			name: "RawSelinuxProfile",
			current: &selinuxprofileapi.RawSelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: selinuxprofileapi.SelinuxProfileStatus{
					StatusBase: profilebaseapi.StatusBase{Status: secprofnodestatusapi.ProfileStateInstalled},
				},
			},
		},
		{
			name: "AppArmorProfile",
			current: &apparmorapi.AppArmorProfile{
				ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
				Status: apparmorapi.AppArmorProfileStatus{
					StatusBase: profilebaseapi.StatusBase{Status: secprofnodestatusapi.ProfileStateInstalled},
				},
			},
		},
	}

	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			desired := testCase.current.DeepCopyToStatusBaseIf()
			require.False(t, profileStatusChanged(testCase.current, desired))

			desired.SetAnnotations(map[string]string{"example": "value"})
			require.False(t, profileStatusChanged(testCase.current, desired))

			desired.GetStatusBase().Status = secprofnodestatusapi.ProfileStatePending
			require.True(t, profileStatusChanged(testCase.current, desired))
		})
	}
}

func TestReconcileStatusRetriesConflictWithFreshGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	testScheme := runtime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(testScheme))

	profile := &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "test-profile"},
	}

	getCalls := 0
	apiReader := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(profile).
		WithObjects(profile).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context,
				c client.WithWatch,
				key client.ObjectKey,
				obj client.Object,
				opts ...client.GetOption,
			) error {
				getCalls++

				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	updateCalls := 0
	fakeClient := fake.NewClientBuilder().
		WithScheme(testScheme).
		WithStatusSubresource(profile).
		WithObjects(profile).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(
				ctx context.Context,
				c client.Client,
				subresource string,
				obj client.Object,
				opts ...client.SubResourceUpdateOption,
			) error {
				updateCalls++
				if updateCalls == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: seccompprofileapi.GroupVersion.Group, Resource: "seccompprofiles"},
						obj.GetName(),
						errors.New("simulated conflict"),
					)
				}

				return c.SubResource(subresource).Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := &StatusReconciler{client: fakeClient, reader: apiReader}
	err := r.reconcileStatus(ctx, profile, secprofnodestatusapi.ProfileStateInstalled, logr.Discard())

	require.NoError(t, err)
	require.Equal(t, 2, updateCalls)
	require.Equal(t, 2, getCalls)
}
