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
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
)

// PodTemplateNeedsUpdate reports if the found pod template of a workload
// differs from the configured one.
//
// If the length of the containers or volumes don't match, we clearly need an
// update. This way we avoid the expensive DeepDerivative check, and the volume
// count also catches a pruned trailing volume, which DeepDerivative would
// accept as a prefix match of the longer slice in the found object. The same
// applies to the arguments, environment variables and volume mounts of the
// containers, for example when profiling gets disabled. DeepDerivative also
// ignores fields which are unset in the configured object, like the ones
// defaulted by the API server, so the fields which can get cleared are
// compared explicitly.
func PodTemplateNeedsUpdate(configured, found *corev1.PodTemplateSpec) bool {
	cSpec, fSpec := &configured.Spec, &found.Spec

	return len(cSpec.InitContainers) != len(fSpec.InitContainers) ||
		len(cSpec.Containers) != len(fSpec.Containers) ||
		len(cSpec.Volumes) != len(fSpec.Volumes) ||
		containerListsDiffer(cSpec.InitContainers, fSpec.InitContainers) ||
		containerListsDiffer(cSpec.Containers, fSpec.Containers) ||
		cSpec.PriorityClassName != fSpec.PriorityClassName ||
		!apiequality.Semantic.DeepEqual(cSpec.Affinity, fSpec.Affinity) ||
		!apiequality.Semantic.DeepEqual(cSpec.Tolerations, fSpec.Tolerations) ||
		!apiequality.Semantic.DeepEqual(cSpec.ImagePullSecrets, fSpec.ImagePullSecrets) ||
		!apiequality.Semantic.DeepDerivative(*configured, *found)
}

// containerListsDiffer reports if the containers at the same index have a
// different number of arguments, environment variables or volume mounts, a
// readiness probe on one side only, or different resources or security
// contexts. DeepDerivative ignores fields which are unset in the configured
// container, so these get compared explicitly to detect cleared ones, like a
// removed limit. Both lists are expected to have the same length.
func containerListsDiffer(configured, found []corev1.Container) bool {
	for i := range configured {
		if len(configured[i].Args) != len(found[i].Args) ||
			len(configured[i].Env) != len(found[i].Env) ||
			len(configured[i].VolumeMounts) != len(found[i].VolumeMounts) ||
			(configured[i].ReadinessProbe == nil) != (found[i].ReadinessProbe == nil) ||
			!apiequality.Semantic.DeepEqual(configured[i].Resources, found[i].Resources) ||
			securityContextsDiffer(configured[i].SecurityContext, found[i].SecurityContext) {
			return true
		}
	}

	return false
}

// securityContextsDiffer reports if the security contexts differ. The proc
// mount type is ignored if it is not configured, because the API server may
// default it.
func securityContextsDiffer(configured, found *corev1.SecurityContext) bool {
	if configured != nil && found != nil && configured.ProcMount == nil {
		configured = configured.DeepCopy()
		configured.ProcMount = found.ProcMount
	}

	return !apiequality.Semantic.DeepEqual(configured, found)
}
