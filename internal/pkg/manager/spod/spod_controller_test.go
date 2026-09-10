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

package spod

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

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

func newTestReconciler() *ReconcileSPOd {
	return &ReconcileSPOd{
		baseSPOd:  bindata.Manifest.DeepCopy(),
		record:    record.NewFakeRecorder(100),
		log:       logf.Log,
		namespace: "security-profiles-operator",
	}
}

func Test_configureJsonEnricher(t *testing.T) {
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

	ctr := v1.Container{Name: "json-enricher"}
	newTestReconciler().configureJsonEnricher(cfg, &ctr)

	require.Contains(t, ctr.Args, "--audit-log-interval-seconds=60")
	require.Contains(t, ctr.Args, "--audit-log-maxsize=10")
}

func Test_configureJsonEnricherNilInterval(t *testing.T) {
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

	ctr := v1.Container{Name: "json-enricher"}
	newTestReconciler().configureJsonEnricher(cfg, &ctr)

	for _, arg := range ctr.Args {
		require.NotContains(t, arg, "--audit-log-interval-seconds")
	}

	require.Contains(t, ctr.Args, "--audit-log-maxsize=10")
}

// Test_getConfiguredSPOdDoesNotMutateBase asserts that rendering the SPOd
// leaves the long lived base SPOd untouched. Rendering used to write through
// to the base, which made enabling AppArmor irreversible.
func Test_getConfiguredSPOdDoesNotMutateBase(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()
	before := r.baseSPOd.DeepCopy()

	cfg := &spodapi.SecurityProfilesOperatorDaemon{
		Spec: spodapi.SPODSpec{
			EnableAppArmor:  new(true),
			EnableProfiling: new(true),
			Verbosity:       1,
			Selinux: spodapi.SPODSelinuxConfig{
				Enable:  new(true),
				TypeTag: "unconfined_t",
			},
		},
	}

	_, err := r.getConfiguredSPOd(
		t.Context(), cfg, "image", v1.PullAlways, bindata.CAInjectTypeCertManager,
	)
	require.NoError(t, err)
	require.Equal(t, before, r.baseSPOd, "rendering must not mutate the base SPOd")
}

// Test_getConfiguredSPOdAppArmorIsRevertible asserts that disabling AppArmor
// drops the elevated privileges the AppArmor code path grants to the daemon.
func Test_getConfiguredSPOdAppArmorIsRevertible(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()

	render := func(apparmor bool) *v1.SecurityContext {
		t.Helper()

		cfg := &spodapi.SecurityProfilesOperatorDaemon{
			Spec: spodapi.SPODSpec{EnableAppArmor: &apparmor},
		}

		ds, err := r.getConfiguredSPOd(
			t.Context(), cfg, "image", v1.PullAlways, bindata.CAInjectTypeCertManager,
		)
		require.NoError(t, err)

		return ds.Spec.Template.Spec.Containers[bindata.ContainerIDDaemon].SecurityContext
	}

	off := render(false)
	require.False(t, ptr.Deref(off.Privileged, false))
	require.True(t, ptr.Deref(off.ReadOnlyRootFilesystem, false))

	on := render(true)
	require.True(t, ptr.Deref(on.Privileged, false))
	require.False(t, ptr.Deref(on.ReadOnlyRootFilesystem, true))

	// Turning AppArmor back off must restore the unprivileged security context.
	again := render(false)
	require.False(t, ptr.Deref(again.Privileged, false),
		"daemon must not stay privileged after AppArmor is disabled")
	require.False(t, ptr.Deref(again.AllowPrivilegeEscalation, false))
	require.True(t, ptr.Deref(again.ReadOnlyRootFilesystem, false))
	require.Equal(t, off.RunAsUser, again.RunAsUser)
}

// Test_getConfiguredSPOdEnricherArgsAreRevertible asserts that removing an
// enricher option from the SPOD removes the corresponding argument again.
func Test_getConfiguredSPOdEnricherArgsAreRevertible(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()

	render := func(filters string) []string {
		t.Helper()

		cfg := &spodapi.SecurityProfilesOperatorDaemon{
			Spec: spodapi.SPODSpec{
				Enricher: spodapi.SPODEnricherConfig{
					EnableLogEnricher:  new(true),
					LogEnricherFilters: filters,
				},
			},
		}

		ds, err := r.getConfiguredSPOd(
			t.Context(), cfg, "image", v1.PullAlways, bindata.CAInjectTypeCertManager,
		)
		require.NoError(t, err)

		for i := range ds.Spec.Template.Spec.Containers {
			ctr := &ds.Spec.Template.Spec.Containers[i]
			if ctr.Name == bindata.LogEnricherContainerName {
				return ctr.Args
			}
		}

		t.Fatal("log enricher container not rendered")

		return nil
	}

	// The filter must be applied on the very first render, not one
	// reconciliation later.
	require.Contains(t, render(`{"a":1}`), `--enricher-filters-json={"a":1}`)

	for _, arg := range render("") {
		require.NotContains(t, arg, "--enricher-filters-json")
	}
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
	require.Equal(
		t,
		templateSpec.Volumes[0].Name,
		templateSpec.InitContainers[1].VolumeMounts[0].Name,
	)
	require.Equal(
		t,
		"/usr/share/selinuxd/templates",
		templateSpec.InitContainers[1].VolumeMounts[0].MountPath,
	)
}

func Test_webhookTolerationsFallback(t *testing.T) {
	t.Parallel()

	daemonTolerations := []v1.Toleration{
		{Operator: v1.TolerationOpExists},
	}
	webhookTolerations := []v1.Toleration{
		{
			Key:    "dedicated",
			Value:  "webhook",
			Effect: v1.TaintEffectNoSchedule,
		},
	}

	for _, tc := range []struct {
		name     string
		cfg      *spodapi.SecurityProfilesOperatorDaemon
		expected []v1.Toleration
	}{
		{
			name: "falls back to daemon tolerations when webhook tolerations not set",
			cfg: &spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{
					Scheduling: spodapi.SPODSchedulingConfig{
						Tolerations: daemonTolerations,
					},
				},
			},
			expected: daemonTolerations,
		},
		{
			name: "uses webhook tolerations when set",
			cfg: &spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{
					Scheduling: spodapi.SPODSchedulingConfig{
						Tolerations: daemonTolerations,
					},
					Webhook: spodapi.SPODWebhookConfig{
						Tolerations: webhookTolerations,
					},
				},
			},
			expected: webhookTolerations,
		},
		{
			name: "uses daemon tolerations when webhook tolerations are nil",
			cfg: &spodapi.SecurityProfilesOperatorDaemon{
				Spec: spodapi.SPODSpec{
					Scheduling: spodapi.SPODSchedulingConfig{
						Tolerations: daemonTolerations,
					},
					Webhook: spodapi.SPODWebhookConfig{
						Tolerations: nil,
					},
				},
			},
			expected: daemonTolerations,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tolerations := tc.cfg.Spec.Webhook.Tolerations
			if len(tolerations) == 0 {
				tolerations = tc.cfg.Spec.Scheduling.Tolerations
			}

			require.Equal(t, tc.expected, tolerations)
		})
	}
}
