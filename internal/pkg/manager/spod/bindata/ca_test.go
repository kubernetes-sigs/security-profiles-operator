/*
Copyright 2025 The Kubernetes Authors.

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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCertManagerResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		namespace string
		expected  struct {
			metricsDNSNames []string
			webhookDNSNames []string
		}
	}{
		{
			name:      "default namespace",
			namespace: "default",
			expected: struct {
				metricsDNSNames []string
				webhookDNSNames []string
			}{
				metricsDNSNames: []string{
					"metrics.default",
					"metrics.default.svc",
					"metrics.default.svc.cluster.local",
				},
				webhookDNSNames: []string{
					"webhook-service.default.svc",
					"webhook-service.default.svc.cluster.local",
				},
			},
		},
		{
			name:      "custom namespace",
			namespace: "my-custom-namespace",
			expected: struct {
				metricsDNSNames []string
				webhookDNSNames []string
			}{
				metricsDNSNames: []string{
					"metrics.my-custom-namespace",
					"metrics.my-custom-namespace.svc",
					"metrics.my-custom-namespace.svc.cluster.local",
				},
				webhookDNSNames: []string{
					"webhook-service.my-custom-namespace.svc",
					"webhook-service.my-custom-namespace.svc.cluster.local",
				},
			},
		},
		{
			name:      "security-profiles-operator namespace",
			namespace: "security-profiles-operator",
			expected: struct {
				metricsDNSNames []string
				webhookDNSNames []string
			}{
				metricsDNSNames: []string{
					"metrics.security-profiles-operator",
					"metrics.security-profiles-operator.svc",
					"metrics.security-profiles-operator.svc.cluster.local",
				},
				webhookDNSNames: []string{
					"webhook-service.security-profiles-operator.svc",
					"webhook-service.security-profiles-operator.svc.cluster.local",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resources := GetCertManagerResources(tt.namespace)

			require.Equal(t, tt.namespace, resources.issuer.Namespace)
			require.Equal(t, tt.namespace, resources.metricsCert.Namespace)
			require.Equal(t, tt.namespace, resources.webhookCert.Namespace)

			require.Equal(t, tt.expected.metricsDNSNames, resources.metricsCert.Spec.DNSNames)

			require.Equal(t, tt.expected.webhookDNSNames, resources.webhookCert.Spec.DNSNames)

			require.Equal(t, []string{
				"metrics.security-profiles-operator",
				"metrics.security-profiles-operator.svc",
				"metrics.security-profiles-operator.svc.cluster.local",
			}, metricsCert.Spec.DNSNames, "original metricsCert template should not be modified")

			require.Equal(t, []string{
				"webhook-service.security-profiles-operator.svc",
				"webhook-service.security-profiles-operator.svc.cluster.local",
			}, webhookCert.Spec.DNSNames, "original webhookCert template should not be modified")

			require.Equal(t, issuerName, resources.issuer.Name)
			require.Equal(t, "metrics-cert", resources.metricsCert.Name)
			require.Equal(t, "webhook-cert", resources.webhookCert.Name)
		})
	}
}

func TestGetCertManagerResources_PreservesOtherProperties(t *testing.T) {
	t.Parallel()

	namespace := "test-namespace"
	resources := GetCertManagerResources(namespace)

	require.Equal(t, metricsCert.Spec.IssuerRef, resources.metricsCert.Spec.IssuerRef)
	require.Equal(t, metricsCert.Spec.SecretName, resources.metricsCert.Spec.SecretName)
	require.Equal(t, metricsCert.Spec.Subject, resources.metricsCert.Spec.Subject)
	require.Equal(t, metricsCert.ObjectMeta.Labels, resources.metricsCert.ObjectMeta.Labels)

	require.Equal(t, webhookCert.Spec.IssuerRef, resources.webhookCert.Spec.IssuerRef)
	require.Equal(t, webhookCert.Spec.SecretName, resources.webhookCert.Spec.SecretName)
	require.Equal(t, webhookCert.ObjectMeta.Labels, resources.webhookCert.ObjectMeta.Labels)

	require.Equal(t, issuer.Spec, resources.issuer.Spec)
	require.Equal(t, issuer.ObjectMeta.Labels, resources.issuer.ObjectMeta.Labels)
}
