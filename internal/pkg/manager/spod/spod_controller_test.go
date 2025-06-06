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

package spod

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
)

func Test_addAuditLogConfig(t *testing.T) {
	t.Parallel()

	args := []string{"mercury"}
	args = addAuditLogConfig(args, "venus")

	require.Contains(t, args, "venus")

	args = []string{"planet=earth"}
	args = addAuditLogConfig(args, "planet=mars")
	require.Contains(t, args, "planet=mars")
	require.NotContains(t, args, "planet=earth")

	// Add Once again to ensure its not duplicated
	args = addAuditLogConfig(args, "planet=mars")
	require.Contains(t, args, "planet=mars")
	require.NotContains(t, args, "planet=earth")
}

func Test_getConfiguredJsonEnricher(t *testing.T) {
	t.Parallel()

	valTen := int32(10)
	valEmptyStr := ""

	cfg := &spodv1alpha1.SecurityProfilesOperatorDaemon{
		Spec: spodv1alpha1.SPODSpec{
			JsonEnricherOpt: &spodv1alpha1.JsonEnricherOptions{
				AuditLogIntervalSeconds: 60,
				AuditLogPath:            &valEmptyStr,
				AuditLogMaxSize:         &valTen,
				AuditLogMaxBackups:      &valTen,
				AuditLogMaxAge:          &valTen,
			},
		},
	}

	r := &ReconcileSPOd{
		baseSPOd: &appsv1.DaemonSet{
			Spec: appsv1.DaemonSetSpec{
				Template: v1.PodTemplateSpec{
					Spec: v1.PodSpec{
						Containers: []v1.Container{
							{},
							{},
							{},
							{},
							{
								Name: "test",
								Args: []string{},
							},
						},
					},
				},
			},
		},
	}

	r.getConfiguredJsonEnricher(cfg)
	require.True(t, containsString(r.baseSPOd.Spec.Template.Spec.Containers[4].Args,
		"--audit-log-interval-seconds=60"))
	require.True(t, containsString(r.baseSPOd.Spec.Template.Spec.Containers[4].Args,
		"--audit-log-maxsize=10"))
}

func containsString(slice []string, element string) bool {
	for _, item := range slice {
		if item == element {
			return true
		}
	}

	return false
}
