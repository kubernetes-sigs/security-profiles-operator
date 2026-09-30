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
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func Test_sliceReplaceArg(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args         []string
		arg          string
		wantReplaced bool
		want         []string
	}{
		"replaces the value of the same key": {
			args: []string{"a=1", "b=2"}, arg: "b=3", wantReplaced: true, want: []string{"a=1", "b=3"},
		},
		"value may contain the separator": {
			args: []string{"f={}"}, arg: `f={"a":"b=c"}`, wantReplaced: true, want: []string{`f={"a":"b=c"}`},
		},
		"only the first match gets replaced": {
			args: []string{"a=1", "a=2"}, arg: "a=3", wantReplaced: true, want: []string{"a=3", "a=2"},
		},
		"other key": {args: []string{"a=1"}, arg: "b=2", want: []string{"a=1"}},
		"prefix of a key is no match": {
			args: []string{"--flag-long=1"}, arg: "--flag=2", want: []string{"--flag-long=1"},
		},
		"argument without value": {args: []string{"a=1"}, arg: "a", want: []string{"a=1"}},
		"empty":                  {arg: "a=1"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			args := slices.Clone(tc.args)
			require.Equal(t, tc.wantReplaced, sliceReplaceArg(args, tc.arg))
			require.Equal(t, tc.want, args)
		})
	}
}

func Test_pruneUnmountedVolumes(t *testing.T) {
	t.Parallel()

	podSpec := &v1.PodSpec{
		InitContainers: []v1.Container{{
			VolumeMounts: []v1.VolumeMount{{Name: "init"}},
		}},
		Containers: []v1.Container{
			{VolumeMounts: []v1.VolumeMount{{Name: "mounted"}}},
			{VolumeDevices: []v1.VolumeDevice{{Name: "device"}}},
		},
		Volumes: []v1.Volume{
			{
				Name: "unused-1",
			},
			{Name: "init"},
			{Name: "mounted"},
			{Name: "unused-2"},
			{Name: "device"},
		},
	}

	pruneUnmountedVolumes(podSpec)

	names := make([]string, 0, len(podSpec.Volumes))
	for i := range podSpec.Volumes {
		names = append(names, podSpec.Volumes[i].Name)
	}

	// The order of the kept volumes stays.
	require.Equal(t, []string{"init", "mounted", "device"}, names)

	empty := &v1.PodSpec{Volumes: []v1.Volume{{Name: "unused"}}}
	pruneUnmountedVolumes(empty)
	require.Empty(t, empty.Volumes)
}

func Test_containerListsDiffer(t *testing.T) {
	t.Parallel()

	base := []v1.Container{{
		Args:         []string{"a"},
		Env:          []v1.EnvVar{{Name: "E"}},
		VolumeMounts: []v1.VolumeMount{{Name: "v"}},
	}}

	require.False(t, containerListsDiffer(base, base))
	require.False(t, containerListsDiffer(nil, nil))

	for name, mutate := range map[string]func(*v1.Container){
		"args":         func(c *v1.Container) { c.Args = nil },
		"env":          func(c *v1.Container) { c.Env = append(c.Env, v1.EnvVar{Name: "F"}) },
		"volumeMounts": func(c *v1.Container) { c.VolumeMounts = nil },
	} {
		found := []v1.Container{*base[0].DeepCopy()}
		mutate(&found[0])
		require.True(t, containerListsDiffer(base, found), name)
	}

	// Only the lengths are compared, the content is left to DeepDerivative.
	found := []v1.Container{*base[0].DeepCopy()}
	found[0].Args = []string{"b"}
	require.False(t, containerListsDiffer(base, found))
}

func Test_addCapabilities(t *testing.T) {
	t.Parallel()

	sc := &v1.SecurityContext{}
	addCapabilities(sc, "A", "B")
	addCapabilities(sc, "B", "C")
	require.Equal(t, []v1.Capability{"A", "B", "C"}, sc.Capabilities.Add)
}

func Test_isExecMetadataEnabled(t *testing.T) {
	t.Parallel()

	r := &ReconcileSPOd{}

	for name, tc := range map[string]struct {
		jsonEnricher *bool
		execMetadata *bool
		want         bool
	}{
		"json enricher disabled":           {execMetadata: new(true)},
		"json enricher enabled by default": {jsonEnricher: new(true), want: true},
		"explicitly enabled":               {jsonEnricher: new(true), execMetadata: new(true), want: true},
		"explicitly disabled":              {jsonEnricher: new(true), execMetadata: new(false)},
	} {
		cfg := &spodapi.SecurityProfilesOperatorDaemon{}
		cfg.Spec.Enricher.EnableJsonEnricher = tc.jsonEnricher
		cfg.Spec.Enricher.EnableExecMetadata = tc.execMetadata
		require.Equal(t, tc.want, r.isExecMetadataEnabled(cfg), name)
	}

	r.env.enableJsonEnricher = true
	require.True(t, r.isExecMetadataEnabled(&spodapi.SecurityProfilesOperatorDaemon{}),
		"the environment enables the JSON enricher")
}

func Test_envFlagsFromEnvironment(t *testing.T) {
	t.Setenv(config.EnableLogEnricherEnvKey, "true")
	t.Setenv(config.EnableJsonEnricherEnvKey, "1")
	t.Setenv(config.EnableBpfRecorderEnvKey, "invalid")
	t.Setenv(config.EnableInsecureMetricsAccessEnvKey, "")

	flags := envFlagsFromEnvironment()
	require.Equal(t, envFlags{enableLogEnricher: true, enableJsonEnricher: true}, flags)

	require.True(t, flags.byEnvKey(config.EnableLogEnricherEnvKey))
	require.True(t, flags.byEnvKey(config.EnableJsonEnricherEnvKey))
	require.False(t, flags.byEnvKey(config.EnableBpfRecorderEnvKey))
	require.False(t, flags.byEnvKey(config.EnableInsecureMetricsAccessEnvKey))
	require.False(t, flags.byEnvKey("OTHER"))
}

// renderedContainer returns the rendered container with the given name.
func renderedContainer(t *testing.T, podSpec *v1.PodSpec, name string) *v1.Container {
	t.Helper()

	idx := slices.IndexFunc(podSpec.Containers, func(c v1.Container) bool { return c.Name == name })
	require.GreaterOrEqual(t, idx, 0, "container %s", name)

	return &podSpec.Containers[idx]
}

// The BPF source of the log enricher reads the audit events from the kernel,
// so it gets the BPF capabilities instead of the host log directories.
func Test_getConfiguredSPOdLogEnricherSource(t *testing.T) {
	t.Parallel()

	r := newTestReconciler()
	certManager := bindata.CAInjectTypeCertManager

	for source, tc := range map[spodapi.LogEnricherSource]struct {
		wantLogs bool
		wantBPF  bool
	}{
		spodapi.LogEnricherSourceAuditd: {wantLogs: true},
		spodapi.LogEnricherSourceBpf:    {wantBPF: true},
	} {
		podSpec := renderedPodSpec(t, r, &spodapi.SPODSpec{
			Enricher: spodapi.SPODEnricherConfig{
				EnableLogEnricher: new(true),
				LogEnricherSource: source,
			},
		}, certManager)

		volumes := map[string]bool{}
		for i := range podSpec.Volumes {
			volumes[podSpec.Volumes[i].Name] = true
		}

		requireVolumes(t, volumes, enricherHostVolumes, tc.wantLogs)

		ctr := renderedContainer(t, podSpec, bindata.LogEnricherContainerName)
		require.False(t, *ctr.SecurityContext.Privileged, source)

		for _, capability := range bpfCapabilities {
			require.Equal(
				t,
				tc.wantBPF,
				slices.Contains(ctr.SecurityContext.Capabilities.Add, capability),
				"%s: %s",
				source,
				capability,
			)
		}
	}

	// The JSON enricher still needs the audit logs next to a BPF log enricher.
	r.clientReader = fake.NewClientBuilder().WithObjects(operatorConfigMap(nil)).Build()
	podSpec := renderedPodSpec(t, r, &spodapi.SPODSpec{
		Enricher: spodapi.SPODEnricherConfig{
			EnableLogEnricher:  new(true),
			EnableJsonEnricher: new(true),
			LogEnricherSource:  spodapi.LogEnricherSourceBpf,
		},
	}, certManager)
	require.True(t, slices.ContainsFunc(podSpec.Volumes, func(v v1.Volume) bool {
		return v.Name == "host-auditlog-volume"
	}))

	// The base SPOd keeps the log mounts for the next render.
	base := r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher]
	require.Len(t, base.VolumeMounts, 4)

	manifest := bindata.Manifest.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher]
	require.Equal(t,
		manifest.SecurityContext.Capabilities.Add, base.SecurityContext.Capabilities.Add)
}

// Enabling profiling in the SPOD is the request to reach the endpoint from
// outside the pod, while the binary binds to the loopback interface per
// default.
func Test_profilingEnvsSpo(t *testing.T) {
	t.Parallel()

	envs := profilingEnvsSpo(2)
	require.Contains(t, envs, v1.EnvVar{Name: config.ProfilingEnvKey, Value: "true"})
	require.Contains(t, envs, v1.EnvVar{Name: config.ProfilingPortEnvKey, Value: "6062"})
	require.Contains(t, envs, v1.EnvVar{
		Name: config.ProfilingAddressEnvKey, Value: config.AllInterfacesAddress,
	})
}
