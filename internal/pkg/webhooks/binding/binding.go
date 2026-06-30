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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
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
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch

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

	pod, admissionResponse := p.updatePod(ctx, profilebindings, &req)
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

// podMatchesSelector reports whether the binding's podSelector matches the
// pod's labels. A nil selector matches every pod, an invalid selector is treated
// as non-matching so the binding is skipped rather than blocking pod admission.
func (p *podBinder) podMatchesSelector(
	pod *corev1.Pod, pb *profilebindingapi.ProfileBinding,
) bool {
	if pb.Spec.PodSelector == nil {
		return true
	}

	selector, err := metav1.LabelSelectorAsSelector(pb.Spec.PodSelector)
	if err != nil {
		p.log.Error(err, "invalid podSelector, skipping binding", "binding", pb.Name)

		return false
	}

	return selector.Matches(labels.Set(pod.GetLabels()))
}

func (p *podBinder) updatePod(
	ctx context.Context,
	profilebindings []profilebindingapi.ProfileBinding,
	req *admission.Request,
) (*corev1.Pod, admission.Response) {
	var err error

	var podBindProfile *any

	var containers sync.Map

	var podProfileBinding *profilebindingapi.ProfileBinding

	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}
	podChanged := false

	if req.Operation != "DELETE" {
		pod, err = p.DecodePod(*req)
		if err != nil {
			p.log.Error(err, "failed to decode pod")

			return pod, admission.Errored(http.StatusBadRequest, err)
		}

		initContainerMap(&containers, &pod.Spec)
	}

	for i := range profilebindings {
		profileKind := profilebindings[i].Spec.ProfileRef.Kind

		profileName := profilebindings[i].Spec.ProfileRef.Name

		if req.Operation == "DELETE" {
			if err := p.removePodFromBinding(ctx, podID, &profilebindings[i]); err != nil {
				return pod, admission.Errored(http.StatusInternalServerError, err)
			}

			continue
		}

		// Skip bindings whose podSelector does not match the pod's labels.
		if !p.podMatchesSelector(pod, &profilebindings[i]) {
			continue
		}

		namespacedName := types.NamespacedName{Namespace: req.Namespace, Name: profileName}

		var bindProfile any

		var err error

		switch profileKind {
		case profilebindingapi.ProfileBindingKindSeccompProfile:
			bindProfile, err = p.getSeccompProfile(ctx, namespacedName)
		case profilebindingapi.ProfileBindingKindSelinuxProfile:
			bindProfile, err = p.getSelinuxProfile(ctx, namespacedName)
		case profilebindingapi.ProfileBindingKindAppArmorProfile:
			bindProfile, err = p.getAppArmorProfile(ctx, namespacedName)
		default:
			p.log.Info(fmt.Sprintf("profile kind %s not supported", profileKind))

			continue
		}

		if err != nil {
			// This relies on util.Retry to propagate the last retried error though the tree of wrapped errors when a
			// resource is not found. Without this, the last error when the retried reached the timeout would only be
			// a wait.ErrWaitTimeout error which will never be matched by this if statement.
			if kerrors.IsNotFound(err) {
				p.log.Info("skip binding due to unavailable profile", "profile-kind", profileKind, "profile", namespacedName)
				// When a profile is not found for a pod, the binding should be just skipped. Otherwise all pod CRUD(s)
				// operation in a namespace with binding enabled will be blocked with 500 error. This might also lead
				// to a DoS when a ProfileBinding has a non-existing profileRef.
				continue
			}

			p.log.Error(err, fmt.Sprintf("failed to get %v %#v", profileKind, namespacedName))

			return pod, admission.Errored(http.StatusInternalServerError, err)
		}

		if profilebindings[i].Spec.Image == profilebindingapi.SelectAllContainersImage {
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

func (p *podBinder) getAppArmorProfile(
	ctx context.Context,
	key types.NamespacedName,
) (appArmorProfile *apparmorprofileapi.AppArmorProfile, err error) {
	err = util.Retry(
		func() (retryErr error) {
			appArmorProfile, retryErr = p.GetAppArmorProfile(ctx, key)
			if retryErr != nil {
				return fmt.Errorf("getting profile: %w", retryErr)
			}

			if appArmorProfile.Status.Status == "" {
				return fmt.Errorf("getting profile: %w", ErrProfWithoutStatus)
			}

			return nil
		}, func(inErr error) bool {
			return errors.Is(inErr, ErrProfWithoutStatus) || kerrors.IsNotFound(inErr)
		})
	//nolint:wrapcheck // already wrapped
	return appArmorProfile, err
}

func (p *podBinder) addSecurityContext(
	c *corev1.Container, bindProfile any,
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addSeccompContext(c, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addSelinuxContext(c, v)
	case *apparmorprofileapi.AppArmorProfile:
		podChanged = p.addAppArmorContext(c, v)
	default:
		p.log.Info("Unexpected Profile Type")

		return false
	}

	return podChanged
}

func (p *podBinder) addSeccompContext(
	c *corev1.Container, seccompProfile *seccompprofileapi.SeccompProfile,
) bool {
	profileRef := seccompProfile.Status.LocalhostProfile
	sp := corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &profileRef,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	if c.SecurityContext.SeccompProfile == nil {
		c.SecurityContext.SeccompProfile = &sp

		return true
	}

	// Make sure that the bound profile is really in the pod security context if already a profile
	// exists, otherwise it can be easily overwritten with something less permissive like
	// "type": "Unconfined", even though a specific profile is enforced through a binding.
	if !ptr.Equal(c.SecurityContext.SeccompProfile, &sp) {
		c.SecurityContext.SeccompProfile = &sp

		return true
	}

	return false
}

func (p *podBinder) addSelinuxContext(
	c *corev1.Container, selinuxProfile *selinuxprofileapi.SelinuxProfile,
) bool {
	usage := selinuxProfile.Status.Usage
	sl := corev1.SELinuxOptions{
		Type: usage,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	if c.SecurityContext.SELinuxOptions == nil {
		c.SecurityContext.SELinuxOptions = &sl

		return true
	}

	// Make sure that the bound profile is really in the pod security context if the profile exists,
	// otherwise it can be easily overwritten with something less permissive, even though a specific
	// profile is enforced through a binding.
	if !ptr.Equal(c.SecurityContext.SELinuxOptions, &sl) {
		c.SecurityContext.SELinuxOptions = &sl

		return true
	}

	return false
}

func (p *podBinder) addAppArmorContext(
	c *corev1.Container, appArmorProfile *apparmorprofileapi.AppArmorProfile,
) bool {
	profileName := appArmorProfile.GetProfileName()
	aa := corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}

	if c.SecurityContext.AppArmorProfile == nil {
		c.SecurityContext.AppArmorProfile = &aa

		return true
	}

	// Make sure that the bound profile is really in the pod security context, otherwise
	// it can be easily overwritten with something less permissive, even though a specific
	// profile is enforced through a binding.
	if !ptr.Equal(c.SecurityContext.AppArmorProfile, &aa) {
		c.SecurityContext.AppArmorProfile = &aa

		return true
	}

	return false
}

func (p *podBinder) addPodSecurityContext(
	pod *corev1.Pod, bindProfile any,
) bool {
	var podChanged bool

	switch v := bindProfile.(type) {
	case *seccompprofileapi.SeccompProfile:
		podChanged = p.addPodSeccompContext(pod, v)
	case *selinuxprofileapi.SelinuxProfile:
		podChanged = p.addPodSelinuxContext(pod, v)
	case *apparmorprofileapi.AppArmorProfile:
		podChanged = p.addPodAppArmorContext(pod, v)
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

func (p *podBinder) addPodAppArmorContext(
	pod *corev1.Pod, appArmorProfile *apparmorprofileapi.AppArmorProfile,
) bool {
	podChanged := false
	profileName := appArmorProfile.GetProfileName()
	aa := corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: &profileName,
	}

	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}

	if pod.Spec.SecurityContext.AppArmorProfile != nil {
		p.log.Info("cannot override existing apparmor profile for pod or container")
	} else {
		pod.Spec.SecurityContext.AppArmorProfile = &aa
		podChanged = true
	}

	return podChanged
}

func (p *podBinder) addPodToBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingapi.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.AppendIfNotExists(pb.Status.ActiveWorkloads, podID)
	if err := p.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return fmt.Errorf("add pod to binding: %w", err)
	}

	if !controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.AddFinalizer(pb, finalizer)
	}

	return p.UpdateResource(ctx, p.log, pb, "profilebinding")
}

func (p *podBinder) removePodFromBinding(
	ctx context.Context,
	podID string,
	pb *profilebindingapi.ProfileBinding,
) error {
	pb.Status.ActiveWorkloads = utils.RemoveIfExists(pb.Status.ActiveWorkloads, podID)
	if err := p.UpdateResourceStatus(ctx, p.log, pb, "profilebinding status"); err != nil {
		return fmt.Errorf("remove pod from binding: %w", err)
	}

	if len(pb.Status.ActiveWorkloads) == 0 &&
		controllerutil.ContainsFinalizer(pb, finalizer) {
		controllerutil.RemoveFinalizer(pb, finalizer)
	}

	return p.UpdateResource(ctx, p.log, pb, "profilebinding")
}
