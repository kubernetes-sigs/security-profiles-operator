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

package util

import (
	"context"
	"sync/atomic"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, configv1.Install(s))

	return s
}

func TestTLSWatcherProfileChangeCallback(t *testing.T) {
	t.Parallel()

	initialProfile, err := tlspkg.GetTLSProfileSpec(nil)
	require.NoError(t, err)

	newTLSType := configv1.TLSProfileOldType

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: newTLSType,
			},
		},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()

	var profileChanged atomic.Bool

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    fakeClient,
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: configv1.TLSAdherencePolicyNoOpinion,
		OnProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			profileChanged.Store(true)
		},
	}

	_, err = watcher.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(apiServer),
	})
	require.NoError(t, err)
	require.True(t, profileChanged.Load(), "expected profile change callback to fire")
}

func TestTLSWatcherNoChangeNoCallback(t *testing.T) {
	t.Parallel()

	initialProfile, err := tlspkg.GetTLSProfileSpec(nil)
	require.NoError(t, err)

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
		Spec:       configv1.APIServerSpec{},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()

	var profileChanged atomic.Bool

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    fakeClient,
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: configv1.TLSAdherencePolicyNoOpinion,
		OnProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			profileChanged.Store(true)
		},
	}

	_, err = watcher.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(apiServer),
	})
	require.NoError(t, err)
	require.False(t, profileChanged.Load(), "expected no callback when profile unchanged")
}

func TestTLSWatcherAdherencePolicyChangeCallback(t *testing.T) {
	t.Parallel()

	initialProfile, err := tlspkg.GetTLSProfileSpec(nil)
	require.NoError(t, err)

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
		Spec: configv1.APIServerSpec{
			TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
		},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()

	var policyChanged atomic.Bool

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    fakeClient,
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: configv1.TLSAdherencePolicyNoOpinion,
		OnAdherencePolicyChange: func(_ context.Context, _, _ configv1.TLSAdherencePolicy) {
			policyChanged.Store(true)
		},
	}

	_, err = watcher.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: client.ObjectKeyFromObject(apiServer),
	})
	require.NoError(t, err)
	require.True(t, policyChanged.Load(), "expected adherence policy change callback to fire")
}

func TestTLSWatcherNilCallbacksDoNotPanic(t *testing.T) {
	t.Parallel()

	initialProfile, err := tlspkg.GetTLSProfileSpec(nil)
	require.NoError(t, err)

	newTLSType := configv1.TLSProfileOldType

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: tlspkg.APIServerName},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: newTLSType,
			},
			TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
		},
	}

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    fakeClient,
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: configv1.TLSAdherencePolicyNoOpinion,
	}

	require.NotPanics(t, func() {
		_, err = watcher.Reconcile(context.Background(), reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(apiServer),
		})
	})
	require.NoError(t, err)
}

func TestTLSWatcherAPIServerNotFound(t *testing.T) {
	t.Parallel()

	initialProfile, err := tlspkg.GetTLSProfileSpec(nil)
	require.NoError(t, err)

	scheme := newScheme(t)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	var profileChanged atomic.Bool

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    fakeClient,
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: configv1.TLSAdherencePolicyNoOpinion,
		OnProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			profileChanged.Store(true)
		},
	}

	_, err = watcher.Reconcile(context.Background(), reconcile.Request{
		NamespacedName: client.ObjectKey{Name: tlspkg.APIServerName},
	})
	require.NoError(t, err)
	require.False(t, profileChanged.Load(), "expected no callback when APIServer not found")
}
