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
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

const finalizer = "active-workload-lock"

var ErrProfWithoutStatus = errors.New("profile hasn't been initialized with status")

type podBinder struct {
	impl
	log logr.Logger
}

func RegisterWebhook(server webhook.Server, scheme *runtime.Scheme, c client.Client) {
	server.Register(
		"/mutate-v1-pod-binding",
		&webhook.Admission{
			Handler: &podBinder{
				impl: &defaultImpl{
					client:  c,
					decoder: admission.NewDecoder(scheme),
				},
				log: logf.Log.WithName("binding"),
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
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=core,resources=events,verbs=create
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=security-profiles-operator,resources=leases,verbs=create
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace=security-profiles-operator,resourceNames=security-profiles-operator-webhook-lock,resources=leases,verbs=get;patch;update

// OpenShift (This is ignored in other distros):
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace=security-profiles-operator,resources=securitycontextconstraints,verbs=use

//nolint:gocritic
func (p *podBinder) Handle(ctx context.Context, req admission.Request) admission.Response {
	profileBindings, err := p.ListProfileBindings(ctx, client.InNamespace(req.Namespace))
	if err != nil {
		p.log.Error(err, "could not list profile bindings")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	profilebindings := profileBindings.Items

	pod, admissionResponse := p.updatePod(ctx, profilebindings, req)
	if !cmp.Equal(admissionResponse, admission.Response{}) {
		return admissionResponse
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		p.log.Error(err, "failed to encode pod")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (p *podBinder) updatePod(ctx context.Context, profilebindings []profilebindingv1alpha1.ProfileBinding, req admission.Request) (*corev1.Pod, admission.Response) {
	var err error
	var podBindProfile *interface{}
	var containers sync.Map
	var podProfileBinding *profilebindingv1alpha1.ProfileBinding
	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}
	podChanged := false
	if req.Operation != "DELETE" {
		pod, err = p.impl.DecodePod(req)
		if err != nil {
			p.log.Error(err, "failed to decode pod")
			return pod, admission.Errored(http.StatusBadRequest, err)
		}
		initContainerMap(&containers, &pod.Spec)
	}
	for i := range profilebindings {
		profileKind := profilebindings[i].Spec.ProfileRef.Kind
		if profileKind != profilebindingv1alpha1.ProfileBindingKindSeccompProfile {
			if profileKind != profilebindingv1alpha1.ProfileBindingKindSelinuxProfile {
				p.log.Info(fmt.Sprintf("profile kind %s not yet supported", profileKind))
				continue
			}
		}

		profileName := profilebindings[i].Spec.ProfileRef.Name
		if req.Operation == "DELETE" {
			if err := p.removePodFromBinding(ctx, podID, &profilebindings[i]); err != nil {
				return pod, admission.Errored(http.StatusInternalServerError, err)
			}
			continue
		}
		namespacedName := types.NamespacedName{Namespace: req.Namespace, Name: profileName}
		var bindProfile interface{}
		var err error

		if profileKind == profilebindingv1alpha1.ProfileBindingKindSeccompProfile {
			bindProfile, err = p.getSeccompProfile(ctx, namespacedName)
		}

		if profileKind == profilebindingv1alpha1.ProfileBindingKindSelinuxProfile {
			bindProfile, err = p.getSelinuxProfile(ctx, namespacedName)
		}

		if err != nil {
			p.log.Error(err, fmt.Sprintf("failed to get %v %#v", profileKind, namespacedName))
			return pod, admission.Errored(http.StatusInternalServerError, err)
		}

		if profilebindings[i].Spec.Image == profilebindingv1alpha1.SelectAllContainersImage {
			podBindProfile = &bindProfile
			podProfileBinding = &profilebindings[i]
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

		for j := range containers {
			podChanged = p.addSecurityContext(containers[j], bindProfile)
		}
		if podChanged {
			if err := p.addPodToBinding(ctx, podID, &profilebindings[i]); err != nil {
				return pod, admission.Errored(http.StatusInternalServerError, err)
			}
		}
	}

	if podChanged {
		return pod, admission.Response{}
	}

	if podBindProfile == nil || podProfileBinding == nil {
		return pod, admission.Allowed("pod unchanged")
	}

	if !p.addPodSecurityContext(pod, *podBindProfile) {
		return pod, admission.Allowed("pod unchanged")
	}
	if err := p.addPodToBinding(ctx, podID, podProfileBinding); err != nil {
		return pod, admission.Errored(http.StatusInternalServerError, err)
	}
	return pod, admission.Response{}
}

func (p *podBinder) getSeccompProfile(
	ctx context.Context,
	key types.NamespacedName,
) (seccompProfile *seccompprofileapi.SeccompProfile, err error) {
	err = util.Retry(
		func() (retryErr error) {
			seccompProfile, retryErr = p.GetSeccompProfile(ctx, key)
			if retryErr != nil {
				return fmt.Errorf("getting profile: %w", retryErr)
			}
			if seccompProfile.Status.Status == "" {
				return fmt.Errorf("getting profile: %w", ErrProfWithoutStatus)
			}
			return nil
		}, func(inErr error) bool {
			return errors.Is(inErr, ErrProfWithoutStatus) || kerrors.IsNotFound(inErr)
		})
	//nolint:wrapcheck // already wrapped
	return seccompProfile, err
}

func (p *podBinder) getSelinuxProfile(
	ctx context.Context,
	key types.NamespacedName,
) (selinuxProfile *selinuxprofileapi.SelinuxProfile, err error) {
	err = util.Retry(
		func() (retryErr error) {
			selinuxProfile, retryErr = p.GetSelinuxProfile(ctx, key)
			if retryErr != nil {
				return fmt.Errorf("getting profile: %w", retryErr)
			}
			if selinuxProfile.Status.Status == "" {
				return fmt.Errorf("getting profile:	%w", ErrProfWithoutStatus)
			}
			return nil
		}, func(inErr error) bool {
			return errors.Is(inErr, ErrProfWithoutStatus) || kerrors.IsNotFound(inErr)
		})
	//nolint:wrapcheck // error is already wrapped
	return selinuxProfile, err
}

func (p *podBinder) addSecurityContext(
	c *corev1.Container, bindProfile interface{},
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addSeccompContext(c, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addSelinuxContext(c, v)
	default:
		p.log.Info("Unexpected Profile Type")
		return false
	}
	return podChanged
}

func (p *podBinder) addSeccompContext(
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

func (p *podBinder) addSelinuxContext(
	c *corev1.Container, selinuxProfile *selinuxprofileapi.SelinuxProfile,
) bool {
	podChanged := false
	usage := selinuxProfile.Status.Usage
	sl := corev1.SELinuxOptions{
		Type: usage,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
	if c.SecurityContext.SELinuxOptions != nil {
		p.log.Info("cannot override existing selinux profile for pod or container")
	} else {
		c.SecurityContext.SELinuxOptions = &sl
		podChanged = true
	}
	return podChanged
}

func (p *podBinder) addPodSecurityContext(
	pod *corev1.Pod, bindProfile interface{},
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addPodSeccompContext(pod, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addPodSelinuxContext(pod, v)
	default:
		p.log.Info("Unexpected Profile Type")
		return false
	}
	return podChanged
}

func (p *podBinder) addPodSeccompContext(
	pod *corev1.Pod, seccompProfile *seccompprofileapi.SeccompProfile,
) bool {
	podChanged := false
	profileRef := seccompProfile.Status.LocalhostProfile
	sp := corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileRef,
	}
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.SeccompProfile != nil {
		p.log.Info("cannot override existing seccomp profile for pod or container")
	} else {
		pod.Spec.SecurityContext.SeccompProfile = &sp
		podChanged = true
	}
	return podChanged
}

func (p *podBinder) addPodSelinuxContext(
	pod *corev1.Pod, selinuxProfile *selinuxprofileapi.SelinuxProfile,
) bool {
	podChanged := false
	usage := selinuxProfile.Status.Usage
	sl := corev1.SELinuxOptions{
		Type: usage,
	}

	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.SELinuxOptions != nil {
		p.log.Info("cannot override existing selinux profile for pod or container")
	} else {
		pod.Spec.SecurityContext.SELinuxOptions = &sl
		podChanged = true
	}
	return podChanged
}

func (p *podBinder) addPodToBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingv1alpha1.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.AppendIfNotExists(pb.Status.ActiveWorkloads, podID)
	if err := p.impl.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return fmt.Errorf("add pod to binding: %w", err)
	}
	if !controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.AddFinalizer(pb, finalizer)
	}
	return p.impl.UpdateResource(ctx, p.log, pb, "profilebinding")
}

func (p *podBinder) removePodFromBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingv1alpha1.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.RemoveIfExists(pb.Status.ActiveWorkloads, podID)
	if err := p.impl.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return fmt.Errorf("remove pod from binding: %w", err)
	}
	if len(pb.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.RemoveFinalizer(pb, finalizer)
	}
	return p.impl.UpdateResource(ctx, p.log, pb, "profilebinding")
}
