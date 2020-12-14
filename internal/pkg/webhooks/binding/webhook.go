/*
Copyright 2020 The Kubernetes Authors.

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

package binding

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
)

var log = logf.Log.WithName("pod-resource")

const (
	warnProfileAlreadySet = "cannot override existing seccomp profile for pod or container"
	finalizer             = "active-workload-lock"
)

type podSeccompBinder struct {
	client  client.Client
	decoder *admission.Decoder
}

func RegisterWebhook(server *webhook.Server, c client.Client) {
	server.Register("/mutate-v1-pod", &webhook.Admission{Handler: &podSeccompBinder{client: c}})
}

type containerMap map[string][]*corev1.Container

func newContainerMap(spec *corev1.PodSpec) containerMap {
	res := make(containerMap)
	if spec.Containers != nil {
		for i := range spec.Containers {
			image := spec.Containers[i].Image
			res[image] = append(res[image], &spec.Containers[i])
		}
	}
	if spec.InitContainers != nil {
		for i := range spec.InitContainers {
			image := spec.InitContainers[i].Image
			res[image] = append(res[image], &spec.InitContainers[i])
		}
	}
	return res
}

func (p *podSeccompBinder) Handle(ctx context.Context, req admission.Request) admission.Response { //nolint:gocritic
	profileBindings := &profilebindingv1alpha1.ProfileBindingList{}
	err := p.client.List(ctx, profileBindings, client.InNamespace(req.Namespace))
	if err != nil {
		log.Error(err, "could not list profile bindings")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	profilebindings := profileBindings.Items
	podChanged := false
	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}
	containers := containerMap{}
	if req.Operation != "DELETE" {
		err := p.decoder.Decode(req, pod)
		if err != nil {
			log.Error(err, "failed to decode pod")
			return admission.Errored(http.StatusBadRequest, err)
		}
		containers = newContainerMap(&pod.Spec)
	}
	for i := range profilebindings {
		// TODO(cmurphy): handle profiles kinds other than SeccompProfile
		if profilebindings[i].Spec.ProfileRef.Kind != "SeccompProfile" {
			log.Info(fmt.Sprintf("profile kind %s not yet supported", profilebindings[i].Spec.ProfileRef.Kind))
			continue
		}
		profileName := profilebindings[i].Spec.ProfileRef.Name
		if req.Operation == "DELETE" {
			if err := p.removePodFromBinding(ctx, podID, &profilebindings[i]); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			continue
		}
		c, ok := containers[profilebindings[i].Spec.Image]
		if !ok {
			continue
		}
		seccompProfile := &seccompprofilev1alpha1.SeccompProfile{}
		namespacedName := types.NamespacedName{Namespace: req.Namespace, Name: profileName}
		err = p.client.Get(ctx, namespacedName, seccompProfile)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to get SeccompProfile %#v", namespacedName))
			return admission.Errored(http.StatusInternalServerError, err)
		}
		for j := range c {
			podChanged = p.addSecurityContext(c[j], seccompProfile)
		}
		if podChanged {
			if err := p.addPodToBinding(ctx, podID, &profilebindings[i]); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
		}
	}
	if !podChanged {
		return admission.Allowed("pod unchanged")
	}
	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		log.Error(err, "failed to encode pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (p *podSeccompBinder) addSecurityContext(
	c *corev1.Container, seccompProfile *seccompprofilev1alpha1.SeccompProfile) bool {
	podChanged := false
	profileRef := seccompProfile.Status.LocalhostProfile
	sp := corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileRef,
	}
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
	if c.SecurityContext.SeccompProfile != nil {
		log.Info(warnProfileAlreadySet)
	} else {
		c.SecurityContext.SeccompProfile = &sp
		podChanged = true
	}
	return podChanged
}

func (p *podSeccompBinder) addPodToBinding(
	ctx context.Context, podID string, pb *profilebindingv1alpha1.ProfileBinding) error {
	pb.Status.ActiveWorkloads = appendIfNotExists(pb.Status.ActiveWorkloads, podID)
	if err := updateResource(ctx, p.client.Status(), pb, "profilebinding status"); err != nil {
		return err
	}
	if !controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.AddFinalizer(pb, finalizer)
	}
	return updateResource(ctx, p.client, pb, "profilebinding")
}

func (p *podSeccompBinder) removePodFromBinding(
	ctx context.Context, podID string, pb *profilebindingv1alpha1.ProfileBinding) error {
	pb.Status.ActiveWorkloads = removeIfExists(pb.Status.ActiveWorkloads, podID)
	if err := updateResource(ctx, p.client.Status(), pb, "profilebinding status"); err != nil {
		return err
	}
	if len(pb.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.RemoveFinalizer(pb, finalizer)
	}
	return updateResource(ctx, p.client, pb, "profilebinding")
}

func updateResource(
	ctx context.Context, c client.StatusWriter, pb *profilebindingv1alpha1.ProfileBinding, resource string) error {
	if err := c.Update(ctx, pb); err != nil {
		msg := fmt.Sprintf("failed to update %s", resource)
		log.Error(err, msg)
		return errors.Wrap(err, msg)
	}
	return nil
}

func appendIfNotExists(list []string, item string) []string {
	for _, s := range list {
		if s == item {
			return list
		}
	}
	return append(list, item)
}

func removeIfExists(list []string, item string) []string {
	for i := range list {
		if list[i] == item {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

func (p *podSeccompBinder) InjectDecoder(d *admission.Decoder) error {
	p.decoder = d
	return nil
}
