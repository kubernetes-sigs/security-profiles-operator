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

package execmetadata

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/go-logr/logr"
	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	ExecRequestUid = "SPO_EXEC_REQUEST_UID"
)

type Handler struct {
	log logr.Logger
}

// Ensure ExecMetadataHandler implements admission.Handler at compile time.
var _ admission.Handler = (*Handler)(nil)

func (p Handler) getEphemeralContainerPatch(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0)

	execPodObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &execPodObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.Info("execPodObject before mutate", "execPodObject", execPodObject)

	type void struct{}

	ephemeralContainersWithStatus := make(map[string]void)

	// Name of Ephemeral Containers should be unique.
	// Ref: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#ephemeralcontainer-v1-core .
	//nolint:intrange // This conflicts with (consider pointers or indexing) (gocritic)
	for i := 0; i < len(execPodObject.Status.EphemeralContainerStatuses); i++ {
		ephemeralContainersWithStatus[execPodObject.Status.EphemeralContainerStatuses[i].Name] = void{}
	}

	//nolint:intrange // This conflicts with (consider pointers or indexing) (gocritic)
	for i := 0; i < len(execPodObject.Spec.EphemeralContainers); i++ {
		container := execPodObject.Spec.EphemeralContainers[i]

		_, exists := ephemeralContainersWithStatus[container.Name]
		// You can't change env of a already created ephemeral container.
		if !exists {
			container.Env = removeExistingEnv(container.Env, ExecRequestUid)
			container.Env = append(container.Env, corev1.EnvVar{Name: ExecRequestUid, Value: string(req.UID)})

			patches = append(patches, jsonpatch.JsonPatchOperation{
				Operation: "replace",
				Path:      "/spec/ephemeralContainers/" + strconv.Itoa(i) + "/env",
				Value:     container.Env,
			})
		}
	}

	p.log.Info("execPodObject after mutate", "execPodObject", execPodObject)

	return patches, nil
}

func removeExistingEnv(env []corev1.EnvVar, key string) []corev1.EnvVar {
	indexOfKey := -1

	for i, envVar := range env {
		if envVar.Name == key {
			indexOfKey = i

			break
		}
	}

	// Order of elements in env does not matter
	if indexOfKey != -1 {
		env[indexOfKey] = env[len(env)-1]
		env = env[:len(env)-1]
	}

	return env
}

func (p Handler) getPodExecPatch(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0)

	execObject := corev1.PodExecOptions{}

	if err := json.Unmarshal(req.Object.Raw, &execObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("execObject before mutate", "execObject", execObject)

	execCommand, replaced := replaceRegexMatches(execObject.Command,
		ExecRequestUid+"=.*", fmt.Sprintf("%s=%s", ExecRequestUid, req.UID))

	if !replaced {
		execObject.Command = slices.Insert(execObject.Command, 0, "env",
			fmt.Sprintf("%s=%s", ExecRequestUid, req.UID))
	} else {
		execObject.Command = execCommand
	}

	p.log.V(1).Info("execObject after mutate", "execObject", execObject)

	return append(patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/command",
		Value:     execObject.Command,
	}), nil
}

func replaceRegexMatches(slice []string, pattern, repl string) ([]string, bool) {
	re := regexp.MustCompile(pattern)

	replaced := false

	for i, s := range slice {
		if re.MatchString(s) {
			slice[i] = re.ReplaceAllString(s, repl)
			replaced = true
		}
	}

	return slice, replaced
}

//nolint:gocritic
func (p Handler) Handle(_ context.Context, req admission.Request) admission.Response {
	p.log.V(1).Info("Executing execmetadata webhook")

	patchGenerators := map[string]func(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error){
		"PodExecOptions": p.getPodExecPatch,
		"Pod":            p.getEphemeralContainerPatch,
	}

	patchFunc, ok := patchGenerators[req.Kind.Kind]
	if !ok {
		p.log.V(1).Error(nil, "Unrecognized kind", "kind", req.Kind.Kind)

		return admission.Allowed("pod exec request unmodified")
	}

	jsonPathOps, err := patchFunc(&req)
	if err != nil {
		p.log.Error(err, "Failed to generate json patch", "kind", req.Kind.Kind)

		return admission.Allowed("pod exec request unmodified")
	}

	resp := admission.Patched("UID added to execmetadata", jsonPathOps...)

	// The RequestUid will be used to correlate the log from container and API server
	resp.AuditAnnotations = map[string]string{
		ExecRequestUid: string(req.UID),
	}

	p.log.V(1).Info("response sent", "resp", resp)

	return resp
}

func RegisterWebhook(server webhook.Server) {
	server.Register(
		"/mutate-v1-exec-metadata",
		&webhook.Admission{
			Handler: &Handler{
				log: logf.Log.WithName("execmetadata"),
			},
		},
	)
}
