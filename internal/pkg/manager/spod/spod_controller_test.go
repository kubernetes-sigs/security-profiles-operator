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
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func Test_addAuditLogConfig(t *testing.T) {
	t.Parallel()

	args := []string{"mercury"}
	args = addArgsConfig(args, "venus")

	require.Contains(t, args, "venus")

	args = []string{"planet=earth"}
	args = addArgsConfig(args, "planet=mars")
	require.Contains(t, args, "planet=mars")
	require.NotContains(t, args, "planet=earth")

	// Add Once again to ensure its not duplicated
	args = addArgsConfig(args, "planet=mars")
	require.Contains(t, args, "planet=mars")
	require.NotContains(t, args, "planet=earth")
}

func Test_getConfiguredJsonEnricher(t *testing.T) {
	t.Parallel()

	valTen := int32(10)
	valSixty := int32(60)
	valEmptyStr := ""

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{
				JsonEnricherOptions: &spodapi.JsonEnricherOptions{
					AuditLogIntervalSeconds: &valSixty,
					AuditLogPath:            &valEmptyStr,
					AuditLogMaxSize:         &valTen,
					AuditLogMaxBackups:      &valTen,
					AuditLogMaxAge:          &valTen,
				},
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

func Test_getConfiguredJsonEnricherNilInterval(t *testing.T) {
	t.Parallel()

	valTen := int32(10)

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{
				JsonEnricherOptions: &spodapi.JsonEnricherOptions{
					AuditLogMaxSize:    &valTen,
					AuditLogMaxBackups: &valTen,
					AuditLogMaxAge:     &valTen,
				},
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

	for _, arg := range r.baseSPOd.Spec.Template.Spec.Containers[4].Args {
		require.NotContains(t, arg, "--audit-log-interval-seconds")
	}

	require.True(t, containsString(r.baseSPOd.Spec.Template.Spec.Containers[4].Args,
		"--audit-log-maxsize=10"))
}

func Test_addSelinuxCustomTemplatesVolumeEmpty(t *testing.T) {
	t.Parallel()

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Selinux: spodapi.SPODSelinuxConfig{
				CustomTemplatesConfigMap: "",
			},
		},
	}

	templateSpec := &v1.PodSpec{
		InitContainers: []v1.Container{{Name: bindata.SelinuxPoliciesCopierContainerName}},
	}

	err := addSelinuxCustomTemplatesVolume(cfg, templateSpec)

	require.NoError(t, err)
	require.Empty(t, templateSpec.Volumes)
	require.Empty(t, templateSpec.InitContainers[0].VolumeMounts)
}

func Test_addSelinuxCustomTemplatesNoInitContainer(t *testing.T) {
	t.Parallel()

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Selinux: spodapi.SPODSelinuxConfig{
				CustomTemplatesConfigMap: "test-templates",
			},
		},
	}

	templateSpec := &v1.PodSpec{
		InitContainers: []v1.Container{{Name: "some-other-container"}},
	}

	err := addSelinuxCustomTemplatesVolume(cfg, templateSpec)

	require.Error(t, err)
	require.Empty(t, templateSpec.Volumes)
	require.Empty(t, templateSpec.InitContainers[0].VolumeMounts)
}

func Test_addSelinuxCustomTemplatesVolume(t *testing.T) {
	t.Parallel()

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			Selinux: spodapi.SPODSelinuxConfig{
				CustomTemplatesConfigMap: "test-templates",
			},
		},
	}

	templateSpec := &v1.PodSpec{
		InitContainers: []v1.Container{
			{Name: "some-other-container"},
			{Name: bindata.SelinuxPoliciesCopierContainerName},
		},
	}

	err := addSelinuxCustomTemplatesVolume(cfg, templateSpec)

	require.NoError(t, err)
	require.Len(t, templateSpec.Volumes, 1)
	require.Equal(t, "test-templates", templateSpec.Volumes[0].ConfigMap.Name)
	require.Empty(t, templateSpec.InitContainers[0].VolumeMounts)
	require.Len(t, templateSpec.InitContainers[1].VolumeMounts, 1)
	require.Equal(t, templateSpec.Volumes[0].Name, templateSpec.InitContainers[1].VolumeMounts[0].Name)
	require.Equal(t, "/usr/share/selinuxd/templates", templateSpec.InitContainers[1].VolumeMounts[0].MountPath)
}

func containsString(slice []string, element string) bool {
	return slices.Contains(slice, element)
}
