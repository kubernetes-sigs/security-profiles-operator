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

package bindata

import (
	"context"
	"slices"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// TestUpdateService verifies that UpdateService restores what the operator
// configures of a service, sends no patch for a service which only has the
// defaults of the API server or the additions of others, and keeps those.
func TestUpdateService(t *testing.T) {
	t.Parallel()

	// The metrics service, with a port without protocol and target port.
	configured := GetMetricsService("spo-ns", CAInjectTypeOpenShift)
	configured.Spec.Ports = append(configured.Spec.Ports, corev1.ServicePort{
		Name: "plain", Port: 8080,
	})

	// The ports the way the API server defaults them.
	livePorts := []corev1.ServicePort{
		{
			Name:       "http",
			Protocol:   corev1.ProtocolTCP,
			Port:       443,
			TargetPort: intstr.FromInt32(9443),
		},
		{
			Name:       "plain",
			Protocol:   corev1.ProtocolTCP,
			Port:       8080,
			TargetPort: intstr.FromInt32(8080),
		},
	}

	// live is the configured service the way the API server stores it.
	live := func() *corev1.Service {
		s := configured.DeepCopy()
		s.Spec.Type = corev1.ServiceTypeClusterIP
		s.Spec.ClusterIP = "10.0.0.1"
		s.Spec.Ports = slices.Clone(livePorts)

		return s
	}

	for _, tc := range []struct {
		name   string
		modify func(*corev1.Service)
		patch  bool
	}{
		{name: "defaulted by the API server", modify: func(*corev1.Service) {}},
		{
			name: "label and annotation of someone else",
			modify: func(s *corev1.Service) {
				s.Labels["other"] = "label"
				s.Annotations["other"] = "annotation"
			},
		},
		{
			name:   "added selector key",
			modify: func(s *corev1.Service) { s.Spec.Selector["other"] = "selector" },
			patch:  true,
		},
		{
			name:   "changed target port",
			modify: func(s *corev1.Service) { s.Spec.Ports[0].TargetPort = intstr.FromInt32(1234) },
			patch:  true,
		},
		{
			name:   "removed annotation",
			modify: func(s *corev1.Service) { delete(s.Annotations, openshiftCertAnnotation) },
			patch:  true,
		},
		{
			name: "load balancer with source ranges",
			modify: func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeLoadBalancer
				s.Spec.LoadBalancerSourceRanges = []string{"10.0.0.0/8"}
				s.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
				s.Annotations[corev1.AnnotationLoadBalancerSourceRangesKey] = "10.0.0.0/8"
			},
			patch: true,
		},
		{
			name: "external name with the same ports",
			modify: func(s *corev1.Service) {
				s.Spec.Type = corev1.ServiceTypeExternalName
				s.Spec.ExternalName = "example.org"
				s.Spec.ClusterIP = ""
			},
			patch: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			found := live()
			tc.modify(found)

			patches := 0
			c := fake.NewClientBuilder().WithObjects(found).WithInterceptorFuncs(interceptor.Funcs{
				Patch: func(
					ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch,
					opts ...client.PatchOption,
				) error {
					patches++

					return cl.Patch(ctx, obj, patch, opts...)
				},
			}).Build()

			require.NoError(t, UpdateService(t.Context(), c, logr.Discard(), configured))

			if tc.patch {
				require.Equal(t, 1, patches)
			} else {
				require.Zero(t, patches)
			}

			restored := &corev1.Service{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(configured), restored))
			require.Equal(t, configured.Spec.Selector, restored.Spec.Selector)
			require.Equal(t, livePorts, restored.Spec.Ports)
			require.Equal(t, corev1.ServiceTypeClusterIP, restored.Spec.Type)
			require.Empty(t, restored.Spec.ExternalName)
			require.Empty(t, restored.Spec.LoadBalancerSourceRanges)
			require.Empty(t, restored.Spec.ExternalTrafficPolicy)
			require.NotContains(
				t,
				restored.Annotations,
				corev1.AnnotationLoadBalancerSourceRangesKey,
			)
			require.Equal(
				t, configured.Annotations[openshiftCertAnnotation],
				restored.Annotations[openshiftCertAnnotation],
			)

			for key, value := range found.Labels {
				require.Equal(t, value, restored.Labels[key])
			}

			// A second update finds nothing to do.
			before := patches

			require.NoError(t, UpdateService(t.Context(), c, logr.Discard(), configured))
			require.Equal(t, before, patches)
		})
	}
}

// TestWebhookServiceRestored verifies that a changed webhook service gets
// restored on its own, without an update of the other webhook objects, down
// to a selector key which got added to it.
func TestWebhookServiceRestored(t *testing.T) {
	t.Parallel()

	w := GetWebhook(logr.Discard(), "spo-ns", nil, "image",
		corev1.PullAlways, CAInjectTypeCertManager, nil, nil, false)
	c := webhookTestClient(t)
	require.NoError(t, w.Create(t.Context(), c))

	found := &corev1.Service{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(w.service), found))
	found.Spec.Selector["other"] = "selector"
	found.Spec.Ports[0].TargetPort = intstr.FromInt32(1234)
	found.Labels["other"] = "label"
	require.NoError(t, c.Update(t.Context(), found))

	// The other webhook objects do not need an update for it.
	needsUpdate, err := w.workloadNeedsUpdate(t.Context(), c)
	require.NoError(t, err)
	require.False(t, needsUpdate)

	require.NoError(t, w.UpdateService(t.Context(), c))

	restored := &corev1.Service{}
	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(w.service), restored))
	require.Equal(t, w.service.Spec.Selector, restored.Spec.Selector)
	require.Equal(t, w.service.Spec.Ports[0].TargetPort, restored.Spec.Ports[0].TargetPort)
	require.Equal(t, "label", restored.Labels["other"])
}

// TestUpdateServiceCacheBehind verifies that a service which the cache does
// not know yet, but which exists, like right after the creation of the SPOD
// created it, is a conflict, which the reconciliation retries quietly.
func TestUpdateServiceCacheBehind(t *testing.T) {
	t.Parallel()

	configured := GetMetricsService("spo-ns", CAInjectTypeCertManager)

	c := fake.NewClientBuilder().WithObjects(configured.DeepCopy()).WithInterceptorFuncs(
		interceptor.Funcs{
			Get: func(
				ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object,
				opts ...client.GetOption,
			) error {
				if _, ok := obj.(*corev1.Service); ok {
					return kerrors.NewNotFound(schema.GroupResource{Resource: "services"}, key.Name)
				}

				return cl.Get(ctx, key, obj, opts...)
			},
		},
	).Build()

	err := UpdateService(t.Context(), c, logr.Discard(), configured)
	require.True(t, kerrors.IsConflict(err), "unexpected error: %v", err)
}

// TestUpdateDeploymentCacheBehind verifies that a webhook deployment which the
// cache does not know yet, but which exists, is a conflict, which the
// reconciliation retries quietly. The operator may not patch deployments.
func TestUpdateDeploymentCacheBehind(t *testing.T) {
	t.Parallel()

	w := GetWebhook(logr.Discard(), "spo-ns", nil, "image",
		corev1.PullAlways, CAInjectTypeCertManager, nil, nil, false)

	c := fake.NewClientBuilder().WithObjects(w.deployment.DeepCopy()).WithInterceptorFuncs(
		interceptor.Funcs{
			Get: func(
				ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object,
				opts ...client.GetOption,
			) error {
				if _, ok := obj.(*appsv1.Deployment); ok {
					return kerrors.NewNotFound(
						schema.GroupResource{Resource: "deployments"},
						key.Name,
					)
				}

				return cl.Get(ctx, key, obj, opts...)
			},
			Patch: func(
				context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption,
			) error {
				t.Error("unexpected patch")

				return nil
			},
		},
	).Build()

	err := updateDeployment(t.Context(), c, w.deployment.DeepCopy())
	require.True(t, kerrors.IsConflict(err), "unexpected error: %v", err)
}
