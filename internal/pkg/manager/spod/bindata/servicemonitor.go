/*
Copyright 2021 The Kubernetes Authors.

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
	v1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// ServiceMonitor returns the default ServiceMonitor for automatic metrics
// retrieval via the prometheus operator.
func ServiceMonitor() *v1.ServiceMonitor {
	return &v1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-profiles-operator-monitor",
			Namespace: config.GetOperatorNamespace(),
		},
		Spec: v1.ServiceMonitorSpec{
			Endpoints: []v1.Endpoint{
				endpointFor("/metrics"),
				endpointFor("/metrics-spod"),
			},
		},
	}
}

// endpointFor provides a standard endpoint for the given URL path.
func endpointFor(path string) v1.Endpoint {
	return v1.Endpoint{
		Path:     path,
		Interval: "10s",
		Port:     "https",
		Scheme:   "https",
		BearerTokenSecret: corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: "metrics-token",
			},
			Key: "token",
		},
		TLSConfig: &v1.TLSConfig{
			SafeTLSConfig: v1.SafeTLSConfig{
				ServerName: "metrics.security-profiles-operator.svc",
				CA: v1.SecretOrConfigMap{
					Secret: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "metrics-server-cert",
						},
						Key: "tls.crt",
					},
				},
			},
		},
	}
}
