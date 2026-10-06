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
	"net/http"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RecorderForRequest returns the recorder for the request. A dry run request
// must not have side effects, which includes events, so it gets none.
func RecorderForRequest(req *admission.Request, rec *SafeRecorder) *SafeRecorder {
	if ptr.Deref(req.DryRun, false) {
		return nil
	}

	return rec
}

// DecodePod decodes the pod of the request and returns it with its name, which
// is the generate name for a pod without a name yet. It returns the admission
// response instead if the pod cannot be decoded, or if it is a Windows pod:
// the API server rejects seccomp, SELinux and AppArmor settings on those, so
// the mutating webhooks leave them alone.
func DecodePod(
	decoder admission.Decoder, req *admission.Request, log logr.Logger,
) (pod *corev1.Pod, podName string, resp *admission.Response) {
	pod = &corev1.Pod{}
	if err := decoder.Decode(*req, pod); err != nil {
		log.Error(err, "Failed to decode pod")

		return nil, "", new(admission.Errored(http.StatusBadRequest, err))
	}

	podName = req.Name
	if podName == "" {
		podName = pod.GenerateName
	}

	if IsWindowsPod(pod) {
		log.Info("Skipping Windows pod, security profiles do not apply", "pod", podName)

		return nil, "", new(admission.Allowed("windows pod, skipping mutation"))
	}

	return pod, podName, nil
}

// PodPatchResponse returns the response which patches the pod of the request
// into the mutated one, see PodPatch.
func PodPatchResponse(
	decoder admission.Decoder, req *admission.Request, mutated *corev1.Pod,
) admission.Response {
	original := &corev1.Pod{}
	if err := decoder.Decode(*req, original); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	patches := PodPatch(original, mutated)
	if len(patches) == 0 {
		return admission.Allowed("pod unchanged")
	}

	return admission.Patched("", patches...)
}
