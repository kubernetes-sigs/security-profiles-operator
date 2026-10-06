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

package execmetadata

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// fuzzUID is the request UID used by the fuzz tests. The API server sets
// UUIDs, so the UID is not fuzzed.
const fuzzUID = "0f6c5b6e-3c4f-4c1e-9a43-6a3c1f1d2e3f"

func fuzzRequest(subResource string, object, oldObject []byte) *admission.Request {
	return &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:         types.UID(fuzzUID),
		SubResource: subResource,
		Object:      runtime.RawExtension{Raw: object},
		OldObject:   runtime.RawExtension{Raw: oldObject},
	}}
}

// FuzzGetPodExecPatch feeds arbitrary pod exec options into the exec patch.
// A patch always sets a command which carries the request UID exactly once
// for every existing UID assignment, or prefixes the command with env and the
// UID assignment.
func FuzzGetPodExecPatch(f *testing.F) {
	for _, seed := range []string{
		`{"command":["sh","-c","true"],"container":"app"}`,
		`{"command":["env","` + ExecRequestUid + `=old","sh"]}`,
		`{"command":["` + ExecRequestUid + `=a\nb"]}`,
		`{"command":[]}`,
		`{"command":null}`,
		`{}`,
		`[]`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}

	handler := Handler{log: logr.Discard()}
	assignment := ExecRequestUid + "=" + fuzzUID

	f.Fuzz(func(t *testing.T, object []byte) {
		patches, err := handler.getPodExecPatch(fuzzRequest("", object, nil))
		if err != nil {
			return
		}

		var options corev1.PodExecOptions
		require.NoError(t, json.Unmarshal(object, &options))

		require.Len(t, patches, 1)
		require.Equal(t, "add", patches[0].Operation)
		require.Equal(t, "/command", patches[0].Path)

		command, ok := patches[0].Value.([]string)
		require.True(t, ok)

		replaced := 0

		for _, arg := range options.Command {
			if execRequestUidRegex.MatchString(arg) {
				replaced++
			}
		}

		if replaced == 0 {
			require.Len(t, command, len(options.Command)+2)
			require.Equal(t, []string{"env", assignment}, command[:2])
			require.True(t, slices.Equal(options.Command, command[2:]))

			return
		}

		require.Len(t, command, len(options.Command))

		for i, arg := range options.Command {
			if execRequestUidRegex.MatchString(arg) {
				require.Equal(t, assignment, command[i])
			} else {
				require.Equal(t, arg, command[i])
			}
		}
	})
}

// FuzzGetPodPatch feeds arbitrary pods into the pod patch, for node debugging
// pods as well as ephemeral containers. Every patch adds an env list which
// ends with the request UID.
func FuzzGetPodPatch(f *testing.F) {
	for _, seed := range []struct {
		subResource, object, oldObject string
	}{
		{"", `{"spec":{"containers":[{"name":"debugger"}]}}`, ""},
		{"", `{"spec":{"containers":[{"name":"debugger","env":[{"name":"` + ExecRequestUid + `"}]}]}}`, ""},
		{"", `{"spec":{"containers":[]}}`, ""},
		{
			ephemeralContainersSubResource,
			`{"spec":{"ephemeralContainers":[{"name":"a"},{"name":"b"}]},` +
				`"status":{"ephemeralContainerStatuses":[{"name":"a"}]}}`,
			`{"spec":{"ephemeralContainers":[{"name":"a"}]}}`,
		},
		{ephemeralContainersSubResource, `{"spec":{"ephemeralContainers":[{"name":"a"}]}}`, `[`},
		{ephemeralContainersSubResource, `{}`, ""},
		{"status", `{}`, ""},
		{"", `null`, ""},
		{"", ``, ""},
	} {
		f.Add(seed.subResource, []byte(seed.object), []byte(seed.oldObject))
	}

	handler := Handler{log: logr.Discard()}

	f.Fuzz(func(t *testing.T, subResource string, object, oldObject []byte) {
		patches, err := handler.getPodPatch(fuzzRequest(subResource, object, oldObject))
		if err != nil {
			return
		}

		for _, patch := range patches {
			require.Equal(t, "add", patch.Operation)
			require.True(t, strings.HasSuffix(patch.Path, "/env"), patch.Path)

			env, ok := patch.Value.([]corev1.EnvVar)
			require.True(t, ok)
			require.NotEmpty(t, env)
			require.Equal(t, corev1.EnvVar{Name: ExecRequestUid, Value: fuzzUID}, env[len(env)-1])
		}
	})
}
