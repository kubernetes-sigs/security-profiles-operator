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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/clidocs"
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
	t.Setenv(config.RestrictNamespaceEnvKey, "team-spo")

	opts := ctrl.Options{}
	setControllerOptionsForNamespaces(&opts, "spo")
	require.Equal(t,
		map[string]cache.Config{"team-spo": {}, "spo": {}},
		opts.Cache.DefaultNamespaces,
	)

	t.Setenv(config.RestrictNamespaceEnvKey, "")

	opts = ctrl.Options{}
	setControllerOptionsForNamespaces(&opts, "spo")
	require.Nil(t, opts.Cache.DefaultNamespaces)
}

func TestRestrictOperandCache(t *testing.T) {
	t.Parallel()

	opts := ctrl.Options{}
	restrictOperandCache(&opts, "spo", servedAPIs{admissionPolicies: true, certManager: true})

	inNamespace := cache.ByObject{Namespaces: map[string]cache.Config{"spo": {}}}
	byName := func(name string) cache.ByObject {
		return cache.ByObject{Field: fields.OneTermEqualSelector("metadata.name", name)}
	}

	require.Len(t, opts.Cache.ByObject, 12)

	for obj, byObject := range opts.Cache.ByObject {
		switch obj.(type) {
		case *appsv1.DaemonSet, *appsv1.Deployment, *corev1.Service, *policyv1.PodDisruptionBudget,
			*certmanagerv1.Issuer, *certmanagerv1.Certificate:
			require.Equal(t, inNamespace, byObject, "%T", obj)
		case *admissionregv1.MutatingWebhookConfiguration:
			require.Equal(t, byName("spo-mutating-webhook-configuration"), byObject)
		case *admissionregv1.ValidatingWebhookConfiguration:
			require.Equal(t, byName("spo-validating-webhook-configuration"), byObject)
		case *admissionregv1.ValidatingAdmissionPolicy,
			*admissionregv1.ValidatingAdmissionPolicyBinding:
			require.Equal(t, byName("spo-recording-profiles"), byObject, "%T", obj)
		case *corev1.ConfigMap:
			require.Equal(t, cache.ByObject{
				Namespaces: map[string]cache.Config{"spo": {}},
				Field: fields.OneTermEqualSelector(
					"metadata.name",
					"security-profiles-operator-profile",
				),
			}, byObject)
		case *corev1.Pod:
			require.NotNil(t, byObject.Transform)
			require.Nil(t, byObject.Namespaces, "pods are cached in every namespace")
		default:
			require.Failf(t, "unexpected object", "%T", obj)
		}
	}
}

// Kubernetes 1.29 and older do not serve the admission policies, and the
// cache must not be configured for kinds without a REST mapping, otherwise the
// manager cannot be created.
func TestRestrictOperandCacheWithoutAdmissionPolicies(t *testing.T) {
	t.Parallel()

	mapper := meta.NewDefaultRESTMapper(nil)

	for _, gvk := range []schema.GroupVersionKind{
		appsv1.SchemeGroupVersion.WithKind("DaemonSet"),
		appsv1.SchemeGroupVersion.WithKind("Deployment"),
		corev1.SchemeGroupVersion.WithKind("Service"),
		corev1.SchemeGroupVersion.WithKind("Pod"),
		corev1.SchemeGroupVersion.WithKind("ConfigMap"),
		policyv1.SchemeGroupVersion.WithKind("PodDisruptionBudget"),
	} {
		mapper.Add(gvk, meta.RESTScopeNamespace)
	}

	for _, gvk := range []schema.GroupVersionKind{
		admissionregv1.SchemeGroupVersion.WithKind("MutatingWebhookConfiguration"),
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingWebhookConfiguration"),
	} {
		mapper.Add(gvk, meta.RESTScopeRoot)
	}

	served, err := spod.ServesAdmissionPolicies(mapper)
	require.NoError(t, err)
	require.False(t, served)

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, certmanagerv1.AddToScheme(scheme))

	newCache := func(served servedAPIs) error {
		opts := ctrl.Options{}
		restrictOperandCache(&opts, "spo", served)

		opts.Cache.Mapper = mapper
		opts.Cache.Scheme = scheme

		_, err := cache.New(&rest.Config{Host: "https://127.0.0.1:1"}, opts.Cache)

		return err
	}

	require.NoError(t, newCache(servedAPIs{admissionPolicies: served}))
	require.Error(
		t,
		newCache(servedAPIs{admissionPolicies: true}),
		"the policies have no REST mapping",
	)
	require.Error(t, newCache(servedAPIs{certManager: true}), "cert-manager has no REST mapping")

	certManagerServed, err := spod.ServesCertManager(mapper)
	require.NoError(t, err)
	require.False(t, certManagerServed)

	for _, kind := range []string{"Issuer", "Certificate"} {
		mapper.Add(certmanagerv1.SchemeGroupVersion.WithKind(kind), meta.RESTScopeNamespace)
	}

	certManagerServed, err = spod.ServesCertManager(mapper)
	require.NoError(t, err)
	require.True(t, certManagerServed)
	require.NoError(t, newCache(servedAPIs{certManager: true}))

	opts := ctrl.Options{}
	restrictOperandCache(&opts, "spo", servedAPIs{})
	require.Len(t, opts.Cache.ByObject, 8)

	for obj := range opts.Cache.ByObject {
		switch obj.(type) {
		case *admissionregv1.ValidatingAdmissionPolicy,
			*admissionregv1.ValidatingAdmissionPolicyBinding,
			*certmanagerv1.Issuer, *certmanagerv1.Certificate:
			require.Failf(t, "unserved kind in the cache options", "%T", obj)
		}
	}
}

func TestStripPod(t *testing.T) {
	t.Parallel()

	sc := &corev1.SecurityContext{RunAsUser: new(int64(1000))}
	ctr := corev1.Container{
		Name:            "ctr",
		Image:           "image",
		SecurityContext: sc,
		Env:             []corev1.EnvVar{{Name: "SECRET", Value: "value"}},
		EnvFrom:         []corev1.EnvFromSource{{Prefix: "p"}},
		Command:         []string{"cmd"},
		Args:            []string{"arg"},
		VolumeMounts:    []corev1.VolumeMount{{Name: "v"}},
		VolumeDevices:   []corev1.VolumeDevice{{Name: "d"}},
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{corev1.ResourceCPU: {}},
		},
		LivenessProbe:  &corev1.Probe{},
		ReadinessProbe: &corev1.Probe{},
		StartupProbe:   &corev1.Probe{},
		Lifecycle:      &corev1.Lifecycle{},
		Ports:          []corev1.ContainerPort{{ContainerPort: 1}},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:          "pod",
			UID:           "uid",
			Labels:        map[string]string{"l": "v"},
			Annotations:   map[string]string{"a": "v"},
			ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "m"}},
		},
		Spec: corev1.PodSpec{
			NodeName:        "node",
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: new(true)},
			Volumes:         []corev1.Volume{{Name: "v"}},
			Containers:      []corev1.Container{*ctr.DeepCopy()},
			InitContainers:  []corev1.Container{*ctr.DeepCopy()},
			EphemeralContainers: []corev1.EphemeralContainer{{
				EphemeralContainerCommon: corev1.EphemeralContainerCommon(*ctr.DeepCopy()),
			}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}

	got, err := stripPod(pod)
	require.NoError(t, err)

	stripped, ok := got.(*corev1.Pod)
	require.True(t, ok)

	// Everything the controllers read stays.
	require.Equal(t, "pod", stripped.Name)
	require.Equal(t, types.UID("uid"), stripped.UID)
	require.Equal(t, map[string]string{"l": "v"}, stripped.Labels)
	require.Equal(t, map[string]string{"a": "v"}, stripped.Annotations)
	require.Equal(t, "node", stripped.Spec.NodeName)
	require.True(t, *stripped.Spec.SecurityContext.RunAsNonRoot)

	want := corev1.Container{Name: "ctr", Image: "image", SecurityContext: sc}
	require.Equal(t, []corev1.Container{want}, stripped.Spec.Containers)
	require.Equal(t, []corev1.Container{want}, stripped.Spec.InitContainers)
	require.Equal(t, corev1.EphemeralContainerCommon(want),
		stripped.Spec.EphemeralContainers[0].EphemeralContainerCommon)

	// Everything else is gone.
	require.Nil(t, stripped.ManagedFields)
	require.Nil(t, stripped.Spec.Volumes)
	require.Equal(t, corev1.PodStatus{}, stripped.Status)

	// Other objects are passed through.
	node := &corev1.Node{}
	got, err = stripPod(node)
	require.NoError(t, err)
	require.Same(t, node, got)
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
		clidocs.Command(newApp, runtimeEnvVars),
	} {
		for _, name := range c.Names() {
			require.False(t, names[name], "duplicate command name or alias %s", name)
			names[name] = true
		}
	}

	require.NotEmpty(t, globalFlags())
}

func TestDocsCommand(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	app := newApp()
	app.Writer = &out

	require.NoError(t, app.Run([]string{config.OperatorName, clidocs.CommandName}))
	require.True(t, strings.HasPrefix(out.String(), "<!-- Code generated by"))
	require.Contains(t, out.String(), "\n# security-profiles-operator command line reference\n")
	require.Contains(t, out.String(), "\n### daemon, d\n")
	require.Contains(
		t,
		out.String(),
		"| `"+config.EnableSeccompEnvKey+"` | `--with-seccomp` | daemon |\n",
	)
	require.Contains(t, out.String(), "| `"+config.NodeNameEnvKey+"` |")
	require.NotContains(t, out.String(), "### docs")
}

func TestNonRootEnablerKubeletDir(t *testing.T) {
	t.Parallel()

	const nodeName = "node"

	nodeWithLabel := func(value string) *corev1.Node {
		node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
		if value != "" {
			node.Labels = map[string]string{config.KubeletDirNodeLabelKey: value}
		}

		return node
	}

	for name, tc := range map[string]struct {
		node    *corev1.Node
		getErr  error
		want    string
		wantErr bool
	}{
		"label":         {node: nodeWithLabel("mnt-resource-kubelet"), want: "/mnt/resource/kubelet"},
		"no label":      {node: nodeWithLabel(""), want: "/data/kubelet"},
		"invalid label": {node: nodeWithLabel("usr-bin-kubelet"), want: "/data/kubelet"},
		// A transient API error must not silently pick another directory.
		"API error": {node: nodeWithLabel("mnt-resource-kubelet"), getErr: errTest, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := fake.NewClientBuilder().
				WithObjects(tc.node).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(
						ctx context.Context, c client.WithWatch, key client.ObjectKey,
						obj client.Object, opts ...client.GetOption,
					) error {
						if tc.getErr != nil {
							return tc.getErr
						}

						return c.Get(ctx, key, obj, opts...)
					},
				}).
				Build()

			got, err := nonRootEnablerKubeletDir(
				t.Context(),
				logr.Discard(),
				c,
				nodeName,
				"/data/kubelet",
			)
			if tc.wantErr {
				require.ErrorIs(t, err, tc.getErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
