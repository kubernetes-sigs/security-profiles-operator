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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/go-logr/logr"
	"gomodules.xyz/jsonpatch/v2"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

const (
	ExecRequestUid = "SPO_EXEC_REQUEST_UID"

	// ephemeralContainersSubResource is the pod sub resource used to add
	// ephemeral containers to a running pod, for example by `kubectl debug`.
	ephemeralContainersSubResource = "ephemeralcontainers"
)

var errUnsupportedSubResource = errors.New("unsupported pod sub resource")

var execRequestUidRegex = regexp.MustCompile(`^` + ExecRequestUid + `=.*$`)

type Handler struct {
	log logr.Logger

	// reader looks up the pod of an exec request. Nil skips the lookup.
	reader client.Reader
}

// Ensure ExecMetadataHandler implements admission.Handler at compile time.
var _ admission.Handler = (*Handler)(nil)

// getPodPatch returns the patch for a pod. The API server sends requests for
// the ephemeral containers sub resource with the "pods" resource and the sub
// resource set separately, so the sub resource decides about the patch.
func (p Handler) getPodPatch(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error) {
	switch req.SubResource {
	case "":
		return p.getNodeDebuggingPodPatch(req)
	case ephemeralContainersSubResource:
		return p.getEphemeralContainerPatch(req)
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedSubResource, req.SubResource)
	}
}

func (p Handler) getNodeDebuggingPodPatch(
	req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0, 1)

	podObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &podObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("podObject before mutate", "podObject", podObject)

	if len(podObject.Spec.Containers) == 0 {
		return patches, errors.New("failed to find a container")
	}

	container := podObject.Spec.Containers[0]
	container.Env = removeExistingEnv(container.Env, ExecRequestUid)
	container.Env = append(
		container.Env,
		corev1.EnvVar{Name: ExecRequestUid, Value: string(req.UID)},
	)

	// "add" rather than "replace": Container.Env is omitempty, so the member is
	// absent for a container that declares no environment variables and RFC 6902
	// "replace" on a missing member is an error. "add" upserts in both cases.
	patches = append(patches, jsonpatch.JsonPatchOperation{
		Operation: "add",
		Path:      "/spec/containers/0/env",
		Value:     container.Env,
	})

	p.log.V(1).Info("podObject after mutate", "podObject", podObject)

	return patches, nil
}

func (p Handler) getEphemeralContainerPatch(
	req *admission.Request,
) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0)

	podObject := corev1.Pod{}

	if err := json.Unmarshal(req.Object.Raw, &podObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("podObject before mutate", "execPodObject", podObject)

	// The env of already created ephemeral containers cannot be changed. Their
	// names are unique, see
	// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#ephemeralcontainer-v1-core
	existing := map[string]bool{}

	if len(req.OldObject.Raw) > 0 {
		oldPod := corev1.Pod{}
		if err := json.Unmarshal(req.OldObject.Raw, &oldPod); err != nil {
			return patches, fmt.Errorf("failed to unmarshal old pod object: %w", err)
		}

		for i := range oldPod.Spec.EphemeralContainers {
			existing[oldPod.Spec.EphemeralContainers[i].Name] = true
		}
	}

	for i := range podObject.Status.EphemeralContainerStatuses {
		existing[podObject.Status.EphemeralContainerStatuses[i].Name] = true
	}

	for i := range podObject.Spec.EphemeralContainers {
		container := &podObject.Spec.EphemeralContainers[i]
		if existing[container.Name] {
			continue
		}

		container.Env = removeExistingEnv(container.Env, ExecRequestUid)
		container.Env = append(
			container.Env,
			corev1.EnvVar{Name: ExecRequestUid, Value: string(req.UID)},
		)

		patches = append(patches, jsonpatch.JsonPatchOperation{
			Operation: "add",
			Path:      "/spec/ephemeralContainers/" + strconv.Itoa(i) + "/env",
			Value:     container.Env,
		})
	}

	p.log.V(1).Info("podObject after mutate", "podObject", podObject)

	return patches, nil
}

// removeExistingEnv removes every environment variable with the key, so that
// a duplicated one cannot shadow the variable which gets appended.
func removeExistingEnv(env []corev1.EnvVar, key string) []corev1.EnvVar {
	return slices.DeleteFunc(env, func(envVar corev1.EnvVar) bool {
		return envVar.Name == key
	})
}

func (p Handler) getPodExecPatch(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error) {
	patches := make([]jsonpatch.JsonPatchOperation, 0, 1)

	execObject := corev1.PodExecOptions{}

	if err := json.Unmarshal(req.Object.Raw, &execObject); err != nil {
		return patches, fmt.Errorf("failed to unmarshal pod exec object: %w", err)
	}

	p.log.V(1).Info("execObject before mutate", "execObject", execObject)

	execCommand, replaced := replaceRegexMatches(execObject.Command,
		execRequestUidRegex, fmt.Sprintf("%s=%s", ExecRequestUid, req.UID))

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

// replaceRegexMatches replaces the matches of re in the elements of slice by
// repl. The replacement is literal, so a "$" in it does not refer to a group.
func replaceRegexMatches(slice []string, re *regexp.Regexp, repl string) ([]string, bool) {
	replaced := false

	for i, s := range slice {
		if re.MatchString(s) {
			slice[i] = re.ReplaceAllLiteralString(s, repl)
			replaced = true
		}
	}

	return slice, replaced
}

// isWindowsPodExec returns true if the exec request targets a Windows pod.
// Windows containers have no env command to prefix the exec command with, so
// the command would fail. The request carries only the exec options, so the
// pod gets looked up. If that fails, the request is treated like one for a
// Linux pod, which the vast majority is. The lookup goes to the API server:
// the webhook may only get pods, so it cannot cache them.
func (p Handler) isWindowsPodExec(ctx context.Context, req *admission.Request) bool {
	if p.reader == nil {
		return false
	}

	pod := &corev1.Pod{}
	if err := p.reader.Get(
		ctx,
		client.ObjectKey{Namespace: req.Namespace, Name: req.Name},
		pod,
	); err != nil {
		p.log.Error(err, "Cannot get the pod of the exec request, assuming a Linux pod",
			"namespace", req.Namespace, "pod", req.Name)

		return false
	}

	return utils.IsWindowsPod(pod)
}

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (p Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	p.log.V(1).Info("Executing execmetadata webhook")

	patchGenerators := map[string]func(req *admission.Request) ([]jsonpatch.JsonPatchOperation, error){
		"PodExecOptions": p.getPodExecPatch,
		"Pod":            p.getPodPatch,
	}

	patchFunc, ok := patchGenerators[req.Kind.Kind]
	if !ok {
		p.log.V(1).Info("Unrecognized kind, allowing request", "kind", req.Kind.Kind)

		return admission.Allowed("pod exec request unmodified")
	}

	if req.Kind.Kind == "PodExecOptions" && p.isWindowsPodExec(ctx, &req) {
		p.log.V(1).
			Info("Windows pod, allowing request", "namespace", req.Namespace, "pod", req.Name)

		return admission.Allowed("windows pod exec request unmodified")
	}

	jsonPathOps, err := patchFunc(&req)
	if err != nil {
		p.log.Error(err, "Failed to generate json patch", "kind", req.Kind.Kind)

		// The webhook fails open, but the client learns that the request
		// carries no exec metadata.
		return admission.Allowed("pod exec request unmodified").WithWarnings(
			"the security profiles operator did not add the exec metadata: " + err.Error(),
		)
	}

	resp := admission.Patched("UID added to execmetadata", jsonPathOps...)

	// The RequestUid will be used to correlate the log from container and API server
	resp.AuditAnnotations = map[string]string{
		ExecRequestUid: string(req.UID),
	}

	p.log.V(1).Info("response sent", "resp", resp)

	return resp
}

// Needed to skip the exec requests for Windows pods:
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get

// RegisterWebhook registers the webhook. The reader looks up the pods of exec
// requests, and should read from the API server rather than from a cache,
// because the webhook does not cache pods otherwise.
func RegisterWebhook(server webhook.Server, reader client.Reader) {
	server.Register(
		"/mutate-v1-exec-metadata",
		&webhook.Admission{
			Handler: &Handler{
				log:    logf.Log.WithName("execmetadata"),
				reader: reader,
			},
		},
	)
}
