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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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

// renderedPodSpec renders the SPOd for the given spec and CA injection type
// and returns its pod template spec. It also asserts that every volume mount
// and volume device of the rendered containers is still backed by a volume.
func renderedPodSpec(
	t *testing.T, r *ReconcileSPOd, spec *spodapi.SPODSpec, caInjectType bindata.CAInjectType,
) *v1.PodSpec {
	t.Helper()

	ds, err := r.getConfiguredSPOd(
		t.Context(), &spodapi.SecurityProfilesOperatorDaemon{Spec: *spec},
		"image", v1.PullAlways, caInjectType,
	)
	require.NoError(t, err)

	podSpec := &ds.Spec.Template.Spec

	volumes := map[string]bool{}
	for i := range podSpec.Volumes {
		volumes[podSpec.Volumes[i].Name] = true
	}

	for _, containers := range [][]v1.Container{podSpec.InitContainers, podSpec.Containers} {
		for i := range containers {
			for _, mount := range containers[i].VolumeMounts {
				require.True(t, volumes[mount.Name],
					"container %s mounts missing volume %s", containers[i].Name, mount.Name)
			}

			for _, device := range containers[i].VolumeDevices {
				require.True(t, volumes[device.Name],
					"container %s uses missing volume device %s", containers[i].Name, device.Name)
			}
		}
	}

	return podSpec
}

// renderedVolumeNames returns the names of every volume of the SPOd rendered
// for the given spec.
func renderedVolumeNames(
	t *testing.T, r *ReconcileSPOd, spec *spodapi.SPODSpec, caInjectType bindata.CAInjectType,
) map[string]bool {
	t.Helper()

	podSpec := renderedPodSpec(t, r, spec, caInjectType)

	volumes := map[string]bool{}
	for i := range podSpec.Volumes {
		volumes[podSpec.Volumes[i].Name] = true
	}

	return volumes
}

func requireVolumes(t *testing.T, volumes map[string]bool, names []string, present bool) {
	t.Helper()

	for _, name := range names {
		require.Equal(t, present, volumes[name], "volume %s", name)
	}
}

var (
	selinuxHostVolumes = []string{
		"host-fsselinux-volume", "host-etcselinux-volume", "host-varlibselinux-volume",
	}
	enricherHostVolumes = []string{"host-auditlog-volume", "host-syslog-volume"}
	bpfHostVolumes      = []string{
		"sys-kernel-debug-volume", "sys-kernel-security-volume",
		"sys-kernel-tracing-volume", "host-etc-osrelease-volume",
	}
)

// Test_getConfiguredSPOdVolumesFollowFeatures asserts that the hostPath
// volumes backing optional features are only rendered when a container of
// that feature mounts them. The base SPOd declares all of them
// unconditionally, so a SPOD with SELinux, the enrichers and the bpf recorder
// disabled used to keep the SELinux, audit log and /sys/kernel host paths in
// the DaemonSet on every node.
func Test_getConfiguredSPOdVolumesFollowFeatures(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()
	certManager := bindata.CAInjectTypeCertManager

	// Everything off: none of the SELinux, enricher or bpf host paths are needed.
	off := renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Selinux: spodapi.SPODSelinuxConfig{Enable: new(false)},
	}, certManager)
	requireVolumes(t, off, selinuxHostVolumes, false)
	requireVolumes(t, off, enricherHostVolumes, false)
	requireVolumes(t, off, bpfHostVolumes, false)

	selinux := renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Selinux: spodapi.SPODSelinuxConfig{Enable: new(true)},
	}, certManager)
	requireVolumes(t, selinux, selinuxHostVolumes, true)
	requireVolumes(t, selinux, enricherHostVolumes, false)
	requireVolumes(t, selinux, bpfHostVolumes, false)

	// OpenShift default: Selinux.Enable is unset and getConfiguredSPOd turns
	// SELinux on because of the CA injection type, so the SELinux volumes stay.
	openshift := renderedVolumeNames(t, r, &spodapi.SPODSpec{}, bindata.CAInjectTypeOpenShift)
	requireVolumes(t, openshift, selinuxHostVolumes, true)
	requireVolumes(t, openshift, enricherHostVolumes, false)
	requireVolumes(t, openshift, bpfHostVolumes, false)

	// The same unset Selinux.Enable outside OpenShift keeps SELinux off.
	noSelinux := renderedVolumeNames(t, r, &spodapi.SPODSpec{}, certManager)
	requireVolumes(t, noSelinux, selinuxHostVolumes, false)

	logEnricher := renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Enricher: spodapi.SPODEnricherConfig{EnableLogEnricher: new(true)},
	}, certManager)
	requireVolumes(t, logEnricher, enricherHostVolumes, true)
	requireVolumes(t, logEnricher, selinuxHostVolumes, false)
	requireVolumes(t, logEnricher, bpfHostVolumes, false)

	bpfRecorder := renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Enricher: spodapi.SPODEnricherConfig{EnableBpfRecorder: new(true)},
	}, certManager)
	requireVolumes(t, bpfRecorder, bpfHostVolumes, true)
	requireVolumes(t, bpfRecorder, selinuxHostVolumes, false)
	requireVolumes(t, bpfRecorder, enricherHostVolumes, false)

	// Every render starts from a fresh DeepCopy of baseSPOd, so pruning the
	// rendered copy must not have removed anything from the base itself: a
	// later render with the feature enabled still finds its volumes.
	requireVolumes(t, renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Selinux: spodapi.SPODSelinuxConfig{Enable: new(true)},
	}, certManager), selinuxHostVolumes, true)
}

// Test_getConfiguredSPOdJsonEnricherVolumes asserts that the JSON enricher
// keeps exactly the host paths it mounts: the audit logs and the tracing
// filesystems, but neither /sys/kernel/security nor /etc/os-release, which
// only the bpf recorder needs. It also covers the log output volume read from
// the operator ConfigMap: it is rendered with the enricher enabled and dropped
// with the enricher disabled, where it used to stay in the DaemonSet.
func Test_getConfiguredSPOdJsonEnricherVolumes(t *testing.T) {
	// The JSON enricher volume lookup requires the operator namespace, so
	// this test cannot run in parallel.
	t.Setenv(config.OperatorNamespaceEnvKey, "security-profiles-operator")

	const (
		logVolumeName = "json-enricher-log-output-volume"
		logMountPath  = "/var/log/spo"
		logHostPath   = "/var/log/spo-json-enricher"
	)

	logVolumeSource := &v1.VolumeSource{
		HostPath: &v1.HostPathVolumeSource{Path: logHostPath},
	}
	logVolumeSourceJson, err := json.Marshal(logVolumeSource)
	require.NoError(t, err)

	operatorConfigMap := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      util.OperatorConfigMap,
			Namespace: config.GetOperatorNamespace(),
		},
		Data: map[string]string{
			util.JsonEnricherLogVolumeSourceJson: string(logVolumeSourceJson),
			util.JsonEnricherLogVolumeMountPath:  logMountPath,
		},
	}

	r := newTestReconciler()
	r.clientReader = fake.NewClientBuilder().WithObjects(operatorConfigMap).Build()
	// Like Setup, start from the effective SPOd, which already carries the log
	// volume and its mount when the ConfigMap configures them.
	r.baseSPOd = getEffectiveSPOd(&daemonTunables{
		jsonEnricherLogVolumeSource:    logVolumeSource,
		jsonEnricherLogVolumeMountPath: logMountPath,
	})

	on := renderedPodSpec(t, r, &spodapi.SPODSpec{
		Enricher: spodapi.SPODEnricherConfig{EnableJsonEnricher: new(true)},
	}, bindata.CAInjectTypeCertManager)

	var logVolume *v1.Volume

	for i := range on.Volumes {
		if on.Volumes[i].Name == logVolumeName {
			logVolume = &on.Volumes[i]
		}
	}

	require.NotNil(t, logVolume, "volume %s", logVolumeName)
	require.NotNil(t, logVolume.HostPath)
	require.Equal(t, logHostPath, logVolume.HostPath.Path)

	jsonEnricher := map[string]bool{}
	for i := range on.Volumes {
		jsonEnricher[on.Volumes[i].Name] = true
	}

	requireVolumes(t, jsonEnricher, enricherHostVolumes, true)
	requireVolumes(t, jsonEnricher, []string{
		"sys-kernel-debug-volume", "sys-kernel-tracing-volume",
	}, true)
	requireVolumes(t, jsonEnricher, []string{
		"sys-kernel-security-volume", "host-etc-osrelease-volume",
	}, false)
	requireVolumes(t, jsonEnricher, selinuxHostVolumes, false)

	// With the JSON enricher disabled its log output volume goes too.
	off := renderedVolumeNames(t, r, &spodapi.SPODSpec{
		Enricher: spodapi.SPODEnricherConfig{EnableJsonEnricher: new(false)},
	}, bindata.CAInjectTypeCertManager)
	requireVolumes(t, off, []string{logVolumeName}, false)
	requireVolumes(t, off, enricherHostVolumes, false)
}

func Test_spodNeedsUpdateVolumeCount(t *testing.T) {
	t.Parallel()

	newDS := func(volumes ...string) *appsv1.DaemonSet {
		ds := &appsv1.DaemonSet{}

		podSpec := &ds.Spec.Template.Spec
		for _, name := range volumes {
			podSpec.Volumes = append(podSpec.Volumes, v1.Volume{Name: name})
		}

		return ds
	}

	require.False(t, spodNeedsUpdate(newDS("a", "b", "c"), newDS("a", "b", "c")))
	require.True(t, spodNeedsUpdate(newDS("a", "b"), newDS("a", "b", "c")),
		"dropping the trailing volume needs an update")
	require.True(t, spodNeedsUpdate(newDS("a", "c"), newDS("a", "b", "c")),
		"dropping a middle volume needs an update")
	require.True(t, spodNeedsUpdate(newDS("a", "b", "c", "d"), newDS("a", "b", "c")))
}

func Test_spodNeedsUpdateClearedFields(t *testing.T) {
	t.Parallel()

	for name, set := range map[string]func(*appsv1.DaemonSet){
		"affinity": func(ds *appsv1.DaemonSet) {
			ds.Spec.Template.Spec.Affinity = &v1.Affinity{NodeAffinity: &v1.NodeAffinity{}}
		},
		"tolerations": func(ds *appsv1.DaemonSet) {
			ds.Spec.Template.Spec.Tolerations = []v1.Toleration{{Key: "key"}}
		},
		"priorityClassName": func(ds *appsv1.DaemonSet) {
			ds.Spec.Template.Spec.PriorityClassName = "high"
		},
		"imagePullSecrets": func(ds *appsv1.DaemonSet) {
			ds.Spec.Template.Spec.ImagePullSecrets = []v1.LocalObjectReference{{Name: "secret"}}
		},
		"apparmor annotation": func(ds *appsv1.DaemonSet) {
			ds.Annotations = map[string]string{appArmorAnnotation: "unconfined"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			found := &appsv1.DaemonSet{}
			set(found)

			require.True(t, spodNeedsUpdate(&appsv1.DaemonSet{}, found), "clearing needs an update")
			require.True(t, spodNeedsUpdate(found, &appsv1.DaemonSet{}), "setting needs an update")
			require.False(t, spodNeedsUpdate(found.DeepCopy(), found))
		})
	}
}

// DeepDerivative accepts a configured slice which is a prefix of the found one,
// so a removed trailing argument, like the one of a disabled feature, has to be
// detected by the length checks.
func Test_spodNeedsUpdateRemovedTrailingContainerFields(t *testing.T) {
	t.Parallel()

	for name, set := range map[string]func(*v1.Container){
		"args": func(c *v1.Container) { c.Args = append(c.Args, "--flag") },
		"env":  func(c *v1.Container) { c.Env = append(c.Env, v1.EnvVar{Name: "ENV"}) },
		"volumeMounts": func(c *v1.Container) {
			c.VolumeMounts = append(c.VolumeMounts, v1.VolumeMount{Name: "vol"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			configured := &appsv1.DaemonSet{}
			configured.Spec.Template.Spec.Containers = []v1.Container{{Name: "ctr"}}
			configured.Spec.Template.Spec.InitContainers = []v1.Container{{Name: "init"}}

			foundCtr := configured.DeepCopy()
			set(&foundCtr.Spec.Template.Spec.Containers[0])
			require.True(t, spodNeedsUpdate(configured, foundCtr))

			foundInit := configured.DeepCopy()
			set(&foundInit.Spec.Template.Spec.InitContainers[0])
			require.True(t, spodNeedsUpdate(configured, foundInit))

			require.False(t, spodNeedsUpdate(foundCtr.DeepCopy(), foundCtr))
		})
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
