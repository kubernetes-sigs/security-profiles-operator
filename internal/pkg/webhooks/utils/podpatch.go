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

package utils

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
)

// PodPatch returns the JSON patch which applies the changes of the mutated
// pod to the original one, for the fields which the webhooks mutate: the
// annotations and the seccomp, SELinux and AppArmor settings of the pod and
// container security contexts. A patch computed from the whole marshaled pod
// would drop the fields which the vendored pod type does not know, like the
// ones of a newer API server.
func PodPatch(original, mutated *corev1.Pod) []jsonpatch.JsonPatchOperation {
	patches := annotationPatches(original.Annotations, mutated.Annotations)

	var origPod, mutPod *profileFields
	if original.Spec.SecurityContext != nil {
		origPod = podProfileFields(original.Spec.SecurityContext)
	}

	if mutated.Spec.SecurityContext != nil {
		mutPod = podProfileFields(mutated.Spec.SecurityContext)
	}

	patches = append(patches, securityContextPatches(
		"/spec/securityContext", origPod, mutPod, mutated.Spec.SecurityContext,
	)...)

	for _, list := range []struct {
		path               string
		original, mutated  int
		originalContainers func(int) *corev1.SecurityContext
		mutatedContainers  func(int) *corev1.SecurityContext
	}{
		{
			"/spec/initContainers", len(original.Spec.InitContainers), len(mutated.Spec.InitContainers),
			func(i int) *corev1.SecurityContext { return original.Spec.InitContainers[i].SecurityContext },
			func(i int) *corev1.SecurityContext { return mutated.Spec.InitContainers[i].SecurityContext },
		},
		{
			"/spec/containers", len(original.Spec.Containers), len(mutated.Spec.Containers),
			func(i int) *corev1.SecurityContext { return original.Spec.Containers[i].SecurityContext },
			func(i int) *corev1.SecurityContext { return mutated.Spec.Containers[i].SecurityContext },
		},
		{
			"/spec/ephemeralContainers",
			len(original.Spec.EphemeralContainers), len(mutated.Spec.EphemeralContainers),
			func(i int) *corev1.SecurityContext {
				return original.Spec.EphemeralContainers[i].SecurityContext
			},
			func(i int) *corev1.SecurityContext {
				return mutated.Spec.EphemeralContainers[i].SecurityContext
			},
		},
	} {
		// The webhooks never add or remove containers.
		for i := range min(list.original, list.mutated) {
			orig, mut := list.originalContainers(i), list.mutatedContainers(i)

			var origFields, mutFields *profileFields
			if orig != nil {
				origFields = containerProfileFields(orig)
			}

			if mut != nil {
				mutFields = containerProfileFields(mut)
			}

			patches = append(patches, securityContextPatches(
				list.path+"/"+strconv.Itoa(i)+"/securityContext", origFields, mutFields, mut,
			)...)
		}
	}

	return patches
}

// profileFields are the security context fields which the webhooks mutate.
type profileFields struct {
	seccomp  *corev1.SeccompProfile
	selinux  *corev1.SELinuxOptions
	apparmor *corev1.AppArmorProfile
}

func podProfileFields(sc *corev1.PodSecurityContext) *profileFields {
	return &profileFields{
		seccomp:  sc.SeccompProfile,
		selinux:  sc.SELinuxOptions,
		apparmor: sc.AppArmorProfile,
	}
}

func containerProfileFields(sc *corev1.SecurityContext) *profileFields {
	return &profileFields{
		seccomp:  sc.SeccompProfile,
		selinux:  sc.SELinuxOptions,
		apparmor: sc.AppArmorProfile,
	}
}

// securityContextPatches returns the patches of the security context at the
// path. A security context which did not exist gets added as a whole, which
// then only holds the fields the webhooks set.
func securityContextPatches(
	path string, original, mutated *profileFields, mutatedContext any,
) []jsonpatch.JsonPatchOperation {
	if mutated == nil {
		return nil
	}

	if original == nil {
		return []jsonpatch.JsonPatchOperation{addOperation(path, mutatedContext)}
	}

	patches := objectPatch(path+"/seccompProfile", original.seccomp, mutated.seccomp)
	patches = append(
		patches,
		objectPatch(path+"/appArmorProfile", original.apparmor, mutated.apparmor)...)

	// The webhooks only set the type of the SELinux options and keep the
	// other fields, like the level, which the platform may set.
	switch {
	case equality.Semantic.DeepEqual(original.selinux, mutated.selinux):
	case original.selinux == nil || mutated.selinux == nil:
		patches = append(
			patches,
			objectPatch(path+"/seLinuxOptions", original.selinux, mutated.selinux)...)
	default:
		for _, field := range []struct {
			name              string
			original, mutated string
		}{
			{"user", original.selinux.User, mutated.selinux.User},
			{"role", original.selinux.Role, mutated.selinux.Role},
			{"type", original.selinux.Type, mutated.selinux.Type},
			{"level", original.selinux.Level, mutated.selinux.Level},
		} {
			patches = append(patches, stringPatch(
				path+"/seLinuxOptions/"+field.name, field.original, field.mutated,
			)...)
		}
	}

	return patches
}

// objectPatch returns the patch which replaces the object at the path, if it
// changed.
func objectPatch[T any](path string, original, mutated *T) []jsonpatch.JsonPatchOperation {
	switch {
	case equality.Semantic.DeepEqual(original, mutated):
		return nil
	case mutated == nil:
		return []jsonpatch.JsonPatchOperation{{Operation: "remove", Path: path}}
	default:
		return []jsonpatch.JsonPatchOperation{addOperation(path, mutated)}
	}
}

// stringPatch returns the patch of an omitempty string member.
func stringPatch(path, original, mutated string) []jsonpatch.JsonPatchOperation {
	switch {
	case original == mutated:
		return nil
	case mutated == "":
		return []jsonpatch.JsonPatchOperation{{Operation: "remove", Path: path}}
	default:
		return []jsonpatch.JsonPatchOperation{addOperation(path, mutated)}
	}
}

// annotationPatches returns the patches which turn the original annotations
// into the mutated ones.
func annotationPatches(original, mutated map[string]string) []jsonpatch.JsonPatchOperation {
	if len(original) == 0 {
		if len(mutated) == 0 {
			return nil
		}

		return []jsonpatch.JsonPatchOperation{addOperation("/metadata/annotations", mutated)}
	}

	var patches []jsonpatch.JsonPatchOperation

	for _, key := range sortedKeys(mutated) {
		if value, ok := original[key]; !ok || value != mutated[key] {
			patches = append(patches, addOperation(annotationPath(key), mutated[key]))
		}
	}

	for _, key := range sortedKeys(original) {
		if _, ok := mutated[key]; !ok {
			patches = append(patches, jsonpatch.JsonPatchOperation{
				Operation: "remove", Path: annotationPath(key),
			})
		}
	}

	return patches
}

// annotationPath returns the JSON pointer of the annotation, whose key may
// contain the characters which RFC 6901 escapes.
func annotationPath(key string) string {
	return "/metadata/annotations/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(key)
}

// addOperation returns an "add" operation, which RFC 6902 defines to replace
// an existing member as well. The value is converted into its generic JSON
// form, like the one of a patch computed from JSON documents.
func addOperation(path string, value any) jsonpatch.JsonPatchOperation {
	if raw, err := json.Marshal(value); err == nil {
		var generic any
		if json.Unmarshal(raw, &generic) == nil {
			value = generic
		}
	}

	return jsonpatch.JsonPatchOperation{Operation: "add", Path: path, Value: value}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
