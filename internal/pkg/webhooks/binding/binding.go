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
	"sync"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

const finalizer = "active-workload-lock"

var ErrProfWithoutStatus = errors.New("profile hasn't been initialized with status")

type podSeccompBinder struct {
	impl
	log logr.Logger
}

func RegisterWebhook(server *webhook.Server, c client.Client) {
	server.Register(
		"/mutate-v1-pod-binding",
		&webhook.Admission{
			Handler: &podSeccompBinder{
				impl: &defaultImpl{client: c},
				log:  logf.Log.WithName("binding"),
			},
		},
	)
}

type containerList []*corev1.Container

func initContainerMap(m *sync.Map, spec *corev1.PodSpec) {
	if spec.Containers != nil {
		for i := range spec.Containers {
			image := spec.Containers[i].Image
			value, _ := m.LoadOrStore(image, containerList{})
			cList, ok := value.(containerList)
			if ok {
				m.Store(image, append(cList, &spec.Containers[i]))
			}
		}
	}
	if spec.InitContainers != nil {
		for i := range spec.InitContainers {
			image := spec.InitContainers[i].Image
			value, _ := m.LoadOrStore(image, containerList{})
			cList, ok := value.(containerList)
			if ok {
				m.Store(image, append(cList, &spec.InitContainers[i]))
			}
		}
	}
}

// Security Profiles Operator Webhook RBAC permissions
// nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Leader election
// nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=core,namespace="security-profiles-operator",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update;

// nolint:gocritic
func (p *podSeccompBinder) Handle(ctx context.Context, req admission.Request) admission.Response {
	profileBindings, err := p.ListProfileBindings(ctx, client.InNamespace(req.Namespace))
	if err != nil {
		p.log.Error(err, "could not list profile bindings")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	profilebindings := profileBindings.Items
	podChanged := false
	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}

	var containers sync.Map
	if req.Operation != "DELETE" {
		pod, err = p.impl.DecodePod(req)
		if err != nil {
			p.log.Error(err, "failed to decode pod")
			return admission.Errored(http.StatusBadRequest, err)
		}
		initContainerMap(&containers, &pod.Spec)
	}

	for i := range profilebindings {
		// TODO(cmurphy): handle profiles kinds other than SeccompProfile
		if profilebindings[i].Spec.ProfileRef.Kind != profilebindingv1alpha1.ProfileBindingKindSeccompProfile {
			p.log.Info(fmt.Sprintf("profile kind %s not yet supported", profilebindings[i].Spec.ProfileRef.Kind))
			continue
		}
		profileName := profilebindings[i].Spec.ProfileRef.Name
		if req.Operation == "DELETE" {
			if err := p.removePodFromBinding(ctx, podID, &profilebindings[i]); err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			continue
		}
		value, ok := containers.Load(profilebindings[i].Spec.Image)
		if !ok {
			continue
		}
		containers, ok := value.(containerList)
		if !ok {
			continue
		}

		namespacedName := types.NamespacedName{Namespace: req.Namespace, Name: profileName}
		seccompProfile, err := p.getSeccompProfile(ctx, namespacedName)
		if err != nil {
			p.log.Error(err, fmt.Sprintf("failed to get SeccompProfile %#v", namespacedName))
			return admission.Errored(http.StatusInternalServerError, err)
		}

		for j := range containers {
			podChanged = p.addSecurityContext(containers[j], seccompProfile)
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
		p.log.Error(err, "failed to encode pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (p *podSeccompBinder) getSeccompProfile(
	ctx context.Context,
	key types.NamespacedName,
) (seccompProfile *seccompprofileapi.SeccompProfile, err error) {
	err = util.Retry(
		func() (retryErr error) {
			seccompProfile, retryErr = p.GetSeccompProfile(ctx, key)
			if retryErr != nil {
				return errors.Wrapf(retryErr, "getting profile")
			}
			if seccompProfile.Status.Status == "" {
				return errors.Wrapf(ErrProfWithoutStatus, "getting profile")
			}
			return nil
		}, func(inErr error) bool {
			return errors.Is(inErr, ErrProfWithoutStatus) || kerrors.IsNotFound(inErr)
		})
	// nolint:wrapcheck // already wrapped
	return seccompProfile, err
}

func (p *podSeccompBinder) addSecurityContext(
	c *corev1.Container, seccompProfile *seccompprofileapi.SeccompProfile,
) bool {
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
		p.log.Info("cannot override existing seccomp profile for pod or container")
	} else {
		c.SecurityContext.SeccompProfile = &sp
		podChanged = true
	}
	return podChanged
}

func (p *podSeccompBinder) addPodToBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingv1alpha1.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.AppendIfNotExists(pb.Status.ActiveWorkloads, podID)
	if err := p.impl.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return errors.Wrap(err, "add pod to binding")
	}
	if !controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.AddFinalizer(pb, finalizer)
	}
	return p.impl.UpdateResource(ctx, p.log, pb, "profilebinding")
}

func (p *podSeccompBinder) removePodFromBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingv1alpha1.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.RemoveIfExists(pb.Status.ActiveWorkloads, podID)
	if err := p.impl.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return errors.Wrap(err, "remove pod from binding")
	}
	if len(pb.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.RemoveFinalizer(pb, finalizer)
	}
	return p.impl.UpdateResource(ctx, p.log, pb, "profilebinding")
}

func (p *podSeccompBinder) InjectDecoder(decoder *admission.Decoder) error {
	p.impl.SetDecoder(decoder)
	return nil
}
