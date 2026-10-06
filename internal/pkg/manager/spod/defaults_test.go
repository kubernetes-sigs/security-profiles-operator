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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// applyServerDefaults sets the fields which the API server defaults on the
// DaemonSets and Deployments the controller writes, and round trips the object
// through JSON like a write to the API server, which normalizes the
// quantities. The fake client does neither, so without this a test would not
// notice a comparison which never settles on a real cluster. The proc mount
// type gets defaulted by API servers with the ProcMountType feature.
func applyServerDefaults(t *testing.T, obj client.Object) {
	t.Helper()

	var template *corev1.PodTemplateSpec

	switch o := obj.(type) {
	case *appsv1.DaemonSet:
		template = &o.Spec.Template

		if o.Spec.UpdateStrategy.Type == "" {
			o.Spec.UpdateStrategy.Type = appsv1.RollingUpdateDaemonSetStrategyType
		}

		if o.Spec.UpdateStrategy.Type == appsv1.RollingUpdateDaemonSetStrategyType &&
			o.Spec.UpdateStrategy.RollingUpdate == nil {
			o.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateDaemonSet{
				MaxUnavailable: new(intstr.FromInt32(1)),
				MaxSurge:       new(intstr.FromInt32(0)),
			}
		}

		if o.Spec.RevisionHistoryLimit == nil {
			o.Spec.RevisionHistoryLimit = new(int32(10))
		}
	case *appsv1.Deployment:
		template = &o.Spec.Template

		if o.Spec.Replicas == nil {
			o.Spec.Replicas = new(int32(1))
		}

		if o.Spec.Strategy.Type == "" {
			o.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
		}

		if o.Spec.Strategy.Type == appsv1.RollingUpdateDeploymentStrategyType &&
			o.Spec.Strategy.RollingUpdate == nil {
			o.Spec.Strategy.RollingUpdate = &appsv1.RollingUpdateDeployment{
				MaxUnavailable: new(intstr.FromString("25%")),
				MaxSurge:       new(intstr.FromString("25%")),
			}
		}

		if o.Spec.RevisionHistoryLimit == nil {
			o.Spec.RevisionHistoryLimit = new(int32(10))
		}

		if o.Spec.ProgressDeadlineSeconds == nil {
			o.Spec.ProgressDeadlineSeconds = new(int32(600))
		}
	default:
		return
	}

	defaultPodSpec(&template.Spec)

	raw, err := json.Marshal(obj)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, obj))
}

func defaultPodSpec(spec *corev1.PodSpec) {
	if spec.RestartPolicy == "" {
		spec.RestartPolicy = corev1.RestartPolicyAlways
	}

	if spec.DNSPolicy == "" {
		spec.DNSPolicy = corev1.DNSClusterFirst
	}

	if spec.SchedulerName == "" {
		spec.SchedulerName = corev1.DefaultSchedulerName
	}

	if spec.TerminationGracePeriodSeconds == nil {
		spec.TerminationGracePeriodSeconds = new(int64(corev1.DefaultTerminationGracePeriodSeconds))
	}

	if spec.SecurityContext == nil {
		spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	if spec.DeprecatedServiceAccount == "" {
		spec.DeprecatedServiceAccount = spec.ServiceAccountName
	}

	if spec.EnableServiceLinks == nil {
		spec.EnableServiceLinks = new(true)
	}

	for i := range spec.InitContainers {
		defaultContainer(&spec.InitContainers[i])
	}

	for i := range spec.Containers {
		defaultContainer(&spec.Containers[i])
	}

	for i := range spec.Volumes {
		source := &spec.Volumes[i].VolumeSource

		switch {
		case source.HostPath != nil && source.HostPath.Type == nil:
			source.HostPath.Type = new(corev1.HostPathUnset)
		case source.Secret != nil && source.Secret.DefaultMode == nil:
			source.Secret.DefaultMode = new(corev1.SecretVolumeSourceDefaultMode)
		case source.ConfigMap != nil && source.ConfigMap.DefaultMode == nil:
			source.ConfigMap.DefaultMode = new(corev1.ConfigMapVolumeSourceDefaultMode)
		}
	}
}

func defaultContainer(ctr *corev1.Container) {
	if ctr.TerminationMessagePath == "" {
		ctr.TerminationMessagePath = corev1.TerminationMessagePathDefault
	}

	if ctr.TerminationMessagePolicy == "" {
		ctr.TerminationMessagePolicy = corev1.TerminationMessageReadFile
	}

	if ctr.ImagePullPolicy == "" {
		ctr.ImagePullPolicy = corev1.PullIfNotPresent
		if strings.HasSuffix(ctr.Image, ":latest") || !strings.Contains(ctr.Image, ":") {
			ctr.ImagePullPolicy = corev1.PullAlways
		}
	}

	for i := range ctr.Ports {
		if ctr.Ports[i].Protocol == "" {
			ctr.Ports[i].Protocol = corev1.ProtocolTCP
		}
	}

	for i := range ctr.Env {
		if ref := ctr.Env[i].ValueFrom; ref != nil && ref.FieldRef != nil &&
			ref.FieldRef.APIVersion == "" {
			ref.FieldRef.APIVersion = "v1"
		}
	}

	for _, probe := range []*corev1.Probe{ctr.LivenessProbe, ctr.ReadinessProbe, ctr.StartupProbe} {
		if probe == nil {
			continue
		}

		if probe.TimeoutSeconds == 0 {
			probe.TimeoutSeconds = 1
		}

		if probe.PeriodSeconds == 0 {
			probe.PeriodSeconds = 10
		}

		if probe.SuccessThreshold == 0 {
			probe.SuccessThreshold = 1
		}

		if probe.FailureThreshold == 0 {
			probe.FailureThreshold = 3
		}

		if probe.HTTPGet != nil && probe.HTTPGet.Scheme == "" {
			probe.HTTPGet.Scheme = corev1.URISchemeHTTP
		}
	}

	if ctr.SecurityContext != nil && ctr.SecurityContext.ProcMount == nil {
		ctr.SecurityContext.ProcMount = new(corev1.DefaultProcMount)
	}
}
