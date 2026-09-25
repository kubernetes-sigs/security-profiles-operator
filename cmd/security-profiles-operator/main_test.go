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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
)

var errTest = errors.New("test")

func TestWatchNamespaces(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		namespaces string
		operatorNS string
		want       []string
	}{
		{name: "all namespaces", operatorNS: "spo"},
		{name: "single namespace", namespaces: "ns", operatorNS: "spo", want: []string{"ns", "spo"}},
		{name: "operator namespace only", namespaces: "spo", operatorNS: "spo", want: []string{"spo"}},
		{
			name:       "multiple namespaces",
			namespaces: "a, b,a,,spo",
			operatorNS: "spo",
			want:       []string{"a", "b", "spo"},
		},
		{
			// A substring match used to skip adding the operator namespace.
			name:       "namespace containing the operator namespace",
			namespaces: "team-spo",
			operatorNS: "spo",
			want:       []string{"team-spo", "spo"},
		},
		{name: "unknown operator namespace", namespaces: "a", want: []string{"a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, watchNamespaces(tc.namespaces, tc.operatorNS))
		})
	}
}

func TestSetControllerOptionsForNamespaces(t *testing.T) {
	t.Setenv(config.OperatorNamespaceEnvKey, "spo")
	t.Setenv(config.RestrictNamespaceEnvKey, "team-spo")

	opts := ctrl.Options{}
	setControllerOptionsForNamespaces(&opts)
	require.Equal(t,
		map[string]cache.Config{"team-spo": {}, "spo": {}},
		opts.Cache.DefaultNamespaces,
	)

	t.Setenv(config.RestrictNamespaceEnvKey, "")

	opts = ctrl.Options{}
	setControllerOptionsForNamespaces(&opts)
	require.Nil(t, opts.Cache.DefaultNamespaces)
}

func TestRestrictOperandCache(t *testing.T) {
	t.Parallel()

	opts := ctrl.Options{}
	restrictOperandCache(&opts, "spo")

	want := cache.ByObject{Namespaces: map[string]cache.Config{"spo": {}}}

	require.Len(t, opts.Cache.ByObject, 3)

	for obj, byObject := range opts.Cache.ByObject {
		switch obj.(type) {
		case *appsv1.DaemonSet, *appsv1.Deployment, *corev1.Service:
		default:
			require.Failf(t, "unexpected object", "%T", obj)
		}

		require.Equal(t, want, byObject)
	}
}

func TestSecureMetricsOptions(t *testing.T) {
	t.Parallel()

	opts := secureMetricsOptions(&tlsConfig{})
	require.True(t, opts.SecureServing)
	require.NotNil(t, opts.FilterProvider)
	require.Equal(t, ":8443", opts.BindAddress)
}

func applyTLSOptions(cfg *tlsConfig) *tls.Config {
	c := &tls.Config{}
	for _, opt := range cfg.options {
		opt(c)
	}

	return c
}

func tlsTestClient(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, configv1.AddToScheme(scheme))

	// The fake client sets the resource version on the passed objects, so
	// give every client its own copies for the parallel tests.
	copies := make([]client.Object, 0, len(objs))
	for _, obj := range objs {
		cp, ok := obj.DeepCopyObject().(client.Object)
		require.True(t, ok)

		copies = append(copies, cp)
	}

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(copies...).Build()
}

func TestFetchClusterTLSOptions(t *testing.T) {
	t.Parallel()

	openShift := &configv1.ClusterOperator{
		ObjectMeta: metav1.ObjectMeta{Name: "openshift-apiserver"},
	}
	modern := &configv1.TLSSecurityProfile{
		Type:   configv1.TLSProfileModernType,
		Modern: &configv1.ModernTLSProfile{},
	}

	t.Run("kubernetes uses the go defaults with TLS 1.2", func(t *testing.T) {
		t.Parallel()

		cfg, err := fetchClusterTLSOptions(t.Context(), tlsTestClient(t))
		require.NoError(t, err)
		require.False(t, cfg.isOpenShift)

		c := applyTLSOptions(&cfg)
		require.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
		require.Equal(t, []string{"http/1.1"}, c.NextProtos)
		require.Empty(t, c.CipherSuites)
	})

	t.Run("openshift honors the cluster profile if required", func(t *testing.T) {
		t.Parallel()

		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: modern,
				TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
			},
		}

		cfg, err := fetchClusterTLSOptions(t.Context(), tlsTestClient(t, openShift, apiServer))
		require.NoError(t, err)
		require.True(t, cfg.isOpenShift)
		require.Equal(t, configv1.TLSAdherencePolicyStrictAllComponents, cfg.adherencePolicy)
		require.Equal(t, uint16(tls.VersionTLS13), applyTLSOptions(&cfg).MinVersion)
	})

	t.Run("openshift uses its default profile without adherence", func(t *testing.T) {
		t.Parallel()

		apiServer := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       configv1.APIServerSpec{TLSSecurityProfile: modern},
		}

		cfg, err := fetchClusterTLSOptions(t.Context(), tlsTestClient(t, openShift, apiServer))
		require.NoError(t, err)
		require.True(t, cfg.isOpenShift)
		require.Equal(t, configv1.TLSAdherencePolicyNoOpinion, cfg.adherencePolicy)

		// The intermediate profile is the OpenShift default.
		c := applyTLSOptions(&cfg)
		require.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
		require.NotEmpty(t, c.CipherSuites)
	})

	t.Run("openshift falls back to the default without an APIServer", func(t *testing.T) {
		t.Parallel()

		cfg, err := fetchClusterTLSOptions(t.Context(), tlsTestClient(t, openShift))
		require.NoError(t, err)
		require.True(t, cfg.isOpenShift)
		require.Equal(t, configv1.TLSAdherencePolicyNoOpinion, cfg.adherencePolicy)
		require.NotEmpty(t, cfg.profile.Ciphers)
	})

	t.Run("detection errors are returned", func(t *testing.T) {
		t.Parallel()

		scheme := runtime.NewScheme()
		require.NoError(t, configv1.AddToScheme(scheme))

		cl := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errTest
			},
		}).Build()

		_, err := fetchClusterTLSOptions(t.Context(), cl)
		require.ErrorIs(t, err, errTest)
	})
}

func TestCommands(t *testing.T) {
	t.Parallel()

	info := &version.Info{}
	names := map[string]bool{}

	for _, c := range []interface{ Names() []string }{
		managerCommand(info),
		daemonCommand(info),
		webhookCommand(info),
		nonRootEnablerCommand(info),
		logEnricherCommand(info),
		jsonEnricherCommand(info),
		bpfRecorderCommand(info),
		spocCommand(),
	} {
		for _, name := range c.Names() {
			require.False(t, names[name], "duplicate command name or alias %s", name)
			names[name] = true
		}
	}

	require.NotEmpty(t, globalFlags())
}
