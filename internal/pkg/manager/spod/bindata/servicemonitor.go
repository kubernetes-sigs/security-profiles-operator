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
	"fmt"
	"strings"

	v1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// ServiceMonitor returns the default ServiceMonitor for automatic metrics
// retrieval via the prometheus operator.
func ServiceMonitor(caInjectType CAInjectType) *v1.ServiceMonitor {
	return &v1.ServiceMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "security-profiles-operator-monitor",
			Namespace: config.GetOperatorNamespace(),
		},
		Spec: v1.ServiceMonitorSpec{
			Endpoints: []v1.Endpoint{
				endpointFor("/metrics", caInjectType),
				endpointFor("/metrics-spod", caInjectType),
			},
			Selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "app",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{config.OperatorName},
					},
				},
			},
		},
	}
}

// endpointFor provides a standard endpoint for the given URL path.
func endpointFor(path string, caInjectType CAInjectType) v1.Endpoint {
	ep := v1.Endpoint{
		Path:     path,
		Interval: "10s",
		Port:     "https",
		Scheme:   "https",
		BearerTokenSecret: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: "metrics-token",
			},
			Key: "token",
		},
		TLSConfig: &v1.TLSConfig{
			SafeTLSConfig: v1.SafeTLSConfig{
				ServerName: fmt.Sprintf("metrics.%s.svc", config.GetOperatorNamespace()),
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

	if isOpenShiftSystemInstalled(caInjectType) {
		ep.TLSConfig = &v1.TLSConfig{
			CAFile: "/etc/prometheus/configmaps/serving-certs-ca-bundle/service-ca.crt",
			SafeTLSConfig: v1.SafeTLSConfig{
				ServerName: fmt.Sprintf("metrics.%s.svc", config.GetOperatorNamespace()),
			},
		}
	}
	return ep
}

// isOpenShiftSystemInstalled returns true if the cluster type if openshift
// and the namespace starts with the openshift- prefix which indicates that
// the operator is installed via the openshift catalog and not e.g. upstream
// releases. In this case, we don't want the user to enable the user monitoring
// configMap, but rather everything work OOTB.
func isOpenShiftSystemInstalled(caInjectType CAInjectType) bool {
	return caInjectType == CAInjectTypeOpenShift &&
		strings.HasPrefix(config.GetOperatorNamespace(), "openshift-")
}
