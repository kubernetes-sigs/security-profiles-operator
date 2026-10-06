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
	"testing"

	jsonpatchapply "github.com/evanphx/json-patch/v5"
	"github.com/stretchr/testify/require"
	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
)

// podWithUnknownFields is a pod as a newer API server may send it, with
// fields which the vendored pod type does not know.
const podWithUnknownFields = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "pod",
    "annotations": {"existing": "value", "a/b~c": "old", "gone": "x"}
  },
  "spec": {
    "futurePodField": {"enabled": true},
    "securityContext": {
      "futurePodSecurityField": "keep",
      "seLinuxOptions": {"level": "s0:c1,c2", "type": "old_t"}
    },
    "initContainers": [{"name": "init", "image": "init", "futureContainerField": 1}],
    "containers": [
      {"name": "ctr", "image": "img", "futureContainerField": 2,
       "securityContext": {"futureSecurityField": "keep", "seccompProfile": {"type": "Unconfined"}}},
      {"name": "other", "image": "img"}
    ],
    "ephemeralContainers": [{"name": "debug", "image": "debug", "futureContainerField": 3}]
  }
}`

// applyPatch applies the patch to the raw pod and returns the result as a
// generic JSON object.
func applyPatch(t *testing.T, raw string, patches []jsonpatch.JsonPatchOperation) map[string]any {
	t.Helper()

	patchJSON, err := json.Marshal(patches)
	require.NoError(t, err)

	patch, err := jsonpatchapply.DecodePatch(patchJSON)
	require.NoError(t, err)

	patched, err := patch.Apply([]byte(raw))
	require.NoError(t, err)

	res := map[string]any{}
	require.NoError(t, json.Unmarshal(patched, &res))

	return res
}

func lookup(t *testing.T, obj any, path ...any) any {
	t.Helper()

	for _, p := range path {
		switch key := p.(type) {
		case string:
			m, ok := obj.(map[string]any)
			require.True(t, ok, "%v is no object", obj)

			obj = m[key]
		case int:
			l, ok := obj.([]any)
			require.True(t, ok, "%v is no list", obj)

			obj = l[key]
		}
	}

	return obj
}

func TestPodPatchKeepsUnknownFields(t *testing.T) {
	t.Parallel()

	original := &corev1.Pod{}
	require.NoError(t, json.Unmarshal([]byte(podWithUnknownFields), original))

	mutated := original.DeepCopy()
	mutated.Annotations["new"] = "value"
	mutated.Annotations["a/b~c"] = "new"
	delete(mutated.Annotations, "gone")
	mutated.Spec.SecurityContext.SELinuxOptions.Type = "bound_t"
	mutated.Spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeRuntimeDefault,
	}
	mutated.Spec.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{
		Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: new("profile.json"),
	}
	mutated.Spec.InitContainers[0].SecurityContext = &corev1.SecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault},
	}
	mutated.Spec.EphemeralContainers[0].SecurityContext = &corev1.SecurityContext{
		SELinuxOptions: &corev1.SELinuxOptions{Type: "debug_t"},
	}

	res := applyPatch(t, podWithUnknownFields, PodPatch(original, mutated))

	// The unknown fields are kept.
	require.Equal(t, map[string]any{"enabled": true}, lookup(t, res, "spec", "futurePodField"))
	require.Equal(t, "keep", lookup(t, res, "spec", "securityContext", "futurePodSecurityField"))
	require.InDelta(t, 1, lookup(t, res, "spec", "initContainers", 0, "futureContainerField"), 0)
	require.InDelta(t, 2, lookup(t, res, "spec", "containers", 0, "futureContainerField"), 0)
	require.Equal(t, "keep",
		lookup(t, res, "spec", "containers", 0, "securityContext", "futureSecurityField"))
	require.InDelta(
		t,
		3,
		lookup(t, res, "spec", "ephemeralContainers", 0, "futureContainerField"),
		0,
	)

	// The mutated fields are applied.
	require.Equal(t, map[string]any{"existing": "value", "a/b~c": "new", "new": "value"},
		lookup(t, res, "metadata", "annotations"))
	require.Equal(t, map[string]any{"level": "s0:c1,c2", "type": "bound_t"},
		lookup(t, res, "spec", "securityContext", "seLinuxOptions"))
	require.Equal(t, map[string]any{"type": "RuntimeDefault"},
		lookup(t, res, "spec", "securityContext", "seccompProfile"))
	require.Equal(t, map[string]any{"type": "Localhost", "localhostProfile": "profile.json"},
		lookup(t, res, "spec", "containers", 0, "securityContext", "seccompProfile"))
	require.Equal(t, map[string]any{"appArmorProfile": map[string]any{"type": "RuntimeDefault"}},
		lookup(t, res, "spec", "initContainers", 0, "securityContext"))
	require.Equal(t, map[string]any{"seLinuxOptions": map[string]any{"type": "debug_t"}},
		lookup(t, res, "spec", "ephemeralContainers", 0, "securityContext"))
	require.Nil(t, lookup(t, res, "spec", "containers", 1, "securityContext"))
}

func TestPodPatchUnchanged(t *testing.T) {
	t.Parallel()

	original := &corev1.Pod{}
	require.NoError(t, json.Unmarshal([]byte(podWithUnknownFields), original))

	require.Empty(t, PodPatch(original, original.DeepCopy()))
}

func TestPodPatchAddsAnnotations(t *testing.T) {
	t.Parallel()

	const raw = `{"metadata": {"name": "pod"}, "spec": {"containers": [{"name": "ctr"}]}}`

	original := &corev1.Pod{}
	require.NoError(t, json.Unmarshal([]byte(raw), original))

	mutated := original.DeepCopy()
	mutated.Annotations = map[string]string{"key": "value"}

	res := applyPatch(t, raw, PodPatch(original, mutated))
	require.Equal(t, map[string]any{"key": "value"}, lookup(t, res, "metadata", "annotations"))
}

// The patch creates missing parent objects, removes cleared fields and is
// idempotent: a reinvoked webhook which computes the same mutation on the
// patched pod gets no patch.
func TestPodPatchCreatesParentsAndIsIdempotent(t *testing.T) {
	t.Parallel()

	const raw = `{
  "metadata": {"name": "pod", "annotations": {}},
  "spec": {
    "containers": [
      {"name": "ctr", "securityContext": {"runAsUser": 1000}},
      {"name": "remove", "securityContext": {
        "seccompProfile": {"type": "RuntimeDefault"},
        "seLinuxOptions": {"user": "u", "type": "t"}
      }}
    ],
    "initContainers": [{"name": "init", "securityContext": null}]
  }
}`

	original := &corev1.Pod{}
	require.NoError(t, json.Unmarshal([]byte(raw), original))

	mutate := func(pod *corev1.Pod) *corev1.Pod {
		mutated := pod.DeepCopy()
		mutated.Annotations = map[string]string{"example.com/profile": "p"}
		mutated.Spec.SecurityContext = &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		}
		mutated.Spec.Containers[0].SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{
			Type: "bound_t",
		}
		mutated.Spec.Containers[1].SecurityContext.SeccompProfile = nil
		mutated.Spec.Containers[1].SecurityContext.SELinuxOptions.User = ""
		mutated.Spec.InitContainers[0].SecurityContext = &corev1.SecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		}

		return mutated
	}

	res := applyPatch(t, raw, PodPatch(original, mutate(original)))

	require.Equal(t, map[string]any{"example.com/profile": "p"},
		lookup(t, res, "metadata", "annotations"))
	require.Equal(t, map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		lookup(t, res, "spec", "securityContext"))
	require.Equal(t, map[string]any{
		"runAsUser":      float64(1000),
		"seLinuxOptions": map[string]any{"type": "bound_t"},
	}, lookup(t, res, "spec", "containers", 0, "securityContext"))
	require.Equal(t, map[string]any{"seLinuxOptions": map[string]any{"type": "t"}},
		lookup(t, res, "spec", "containers", 1, "securityContext"))
	require.Equal(t, map[string]any{"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		lookup(t, res, "spec", "initContainers", 0, "securityContext"))

	// A reinvocation sees the patched pod and computes the same mutation.
	patchedRaw, err := json.Marshal(res)
	require.NoError(t, err)

	patched := &corev1.Pod{}
	require.NoError(t, json.Unmarshal(patchedRaw, patched))
	require.Empty(t, PodPatch(patched, mutate(patched)))
}
