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

package bindingtracker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadtracker"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	linkedPodsKey    = ".metadata.bindingActiveWorkloads"
	finalizer        = "active-workload-lock"
	reconcileTimeout = 1 * time.Minute

	// appliedBindingsKey indexes the pods by the bindings the webhook
	// applied to them.
	appliedBindingsKey = ".metadata.annotations.appliedBindings"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &BindingTrackerReconciler{}
}

// BindingTrackerReconciler watches Pods and updates ProfileBinding
// status.ActiveWorkloads and finalizers accordingly.
type BindingTrackerReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
}

func (r *BindingTrackerReconciler) Name() string {
	return "binding-tracker"
}

// SchemeBuilder returns the APIs of the bindings and of the SPOD
// configuration, which tells whether a profile kind is enabled.
func (r *BindingTrackerReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return runtime.NewSchemeBuilder(profilebindingapi.AddToScheme, spodapi.AddToScheme)
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles;selinuxprofiles;apparmorprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,resourceNames=spo-mutating-webhook-configuration,verbs=get;list;watch

func (r *BindingTrackerReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	podID := req.Namespace + "/" + req.Name
	pod := &corev1.Pod{}

	err := r.client.Get(ctx, req.NamespacedName, pod)
	if client.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, fmt.Errorf("getting pod: %w", err)
	}

	if errors.IsNotFound(err) {
		return r.handlePodDeletion(ctx, logger, req.Namespace, podID)
	}

	return r.handlePodCreateOrUpdate(ctx, logger, pod, podID)
}

func (r *BindingTrackerReconciler) handlePodDeletion(
	ctx context.Context,
	logger logr.Logger,
	namespace, podID string,
) (reconcile.Result, error) {
	bindings := &profilebindingapi.ProfileBindingList{}
	if err := r.client.List(
		ctx, bindings,
		client.MatchingFields{linkedPodsKey: podID},
		client.InNamespace(namespace),
	); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing bindings for deleted pod: %w", err)
	}

	for i := range bindings.Items {
		binding := &bindings.Items[i]
		logger.Info("Removing deleted pod from binding", "binding", binding.Name)

		if err := r.untrackPod(ctx, binding, podID); err != nil {
			return reconcile.Result{}, fmt.Errorf("untracking deleted pod: %w", err)
		}
	}

	return reconcile.Result{}, nil
}

func (r *BindingTrackerReconciler) handlePodCreateOrUpdate(
	ctx context.Context,
	logger logr.Logger,
	pod *corev1.Pod,
	podID string,
) (reconcile.Result, error) {
	bindings := &profilebindingapi.ProfileBindingList{}
	if err := r.client.List(ctx, bindings, client.InNamespace(pod.Namespace)); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing bindings: %w", err)
	}

	if len(bindings.Items) == 0 {
		return reconcile.Result{}, nil
	}

	bindingEnabled, err := r.bindingEnabled(ctx, pod)
	if err != nil {
		return reconcile.Result{}, err
	}

	for i := range bindings.Items {
		binding := &bindings.Items[i]
		tracked := slices.Contains(binding.Status.ActiveWorkloads, podID)
		// A completed pod, like the one of a finished Job, does not use the
		// binding anymore, although it exists until it gets deleted.
		uses := !util.PodCompleted(pod) &&
			podAnnotatedWithBinding(binding, pod, tracked, bindingEnabled)

		// The cached binding tells if the pod is tracked already, so a pod
		// update does not cost an API read or a profile lookup per binding.
		if uses && tracked && controllerutil.ContainsFinalizer(binding, finalizer) {
			continue
		}

		// The pod author can change the annotation of the applied bindings
		// after the creation of the pod, unlike its security contexts, so a
		// pod only gets tracked anew if it carries the profile of the
		// binding. A tracked pod stays tracked while it is annotated, also
		// if its profile is gone or has no status by now.
		if uses && !tracked {
			carries, err := r.profileCarrier(ctx, binding)
			if err != nil {
				return reconcile.Result{}, err
			}

			uses = carries(pod)
		}

		// A binding which is being deleted must not track new pods: the API
		// server rejects adding finalizers to it.
		if uses && binding.GetDeletionTimestamp().IsZero() {
			if !tracked {
				logger.Info("Tracking pod in binding", "binding", binding.Name)
			}

			if err := r.trackPod(ctx, binding, podID); err != nil {
				return reconcile.Result{}, err
			}

			continue
		}

		if tracked && !uses {
			logger.Info(
				"Removing pod which no longer matches from binding",
				"binding",
				binding.Name,
			)

			if err := r.untrackPod(ctx, binding, podID); err != nil {
				return reconcile.Result{}, fmt.Errorf("untracking pod: %w", err)
			}
		}
	}

	return reconcile.Result{}, nil
}

// bindingUsers returns the pods which use the binding, which fill up an
// emptied list of active workloads, see workloadtracker.Tracker. They get
// checked like pods tracked anew, including the profile, as the pod author
// can add the annotation of the applied bindings, which would otherwise keep
// the binding from being deleted. Pods created before the webhook set that
// annotation only stay tracked while they are listed, so they are left out.
// The profile and whether the binding webhook selects the namespace are only
// looked up once.
func (r *BindingTrackerReconciler) bindingUsers(
	ctx context.Context, pb *profilebindingapi.ProfileBinding,
) ([]string, error) {
	carries, err := r.profileCarrier(ctx, pb)
	if err != nil {
		return nil, err
	}

	pods := &corev1.PodList{}
	// The pods are only read, so the cache does not have to copy them.
	if err := r.client.List(
		ctx, pods, client.InNamespace(pb.Namespace), client.UnsafeDisableDeepCopy,
	); err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	var (
		users            []string
		namespaceEnabled *bool
	)

	for i := range pods.Items {
		pod := &pods.Items[i]
		if util.PodCompleted(pod) {
			continue
		}

		bindingEnabled := true

		if needsNamespaceCheck(pod) {
			if namespaceEnabled == nil {
				enabled, err := r.namespaceBindingEnabled(ctx, pb.Namespace)
				if err != nil {
					return nil, err
				}

				namespaceEnabled = &enabled
			}

			bindingEnabled = *namespaceEnabled
		}

		if podAnnotatedWithBinding(pb, pod, false, bindingEnabled) && carries(pod) {
			users = append(users, pod.Namespace+"/"+pod.Name)
		}
	}

	return users, nil
}

// tracker tracks the pods in the active workloads of the bindings.
func (r *BindingTrackerReconciler) tracker() *workloadtracker.Tracker[*profilebindingapi.ProfileBinding] {
	return &workloadtracker.Tracker[*profilebindingapi.ProfileBinding]{
		Client:    r.client,
		Reader:    r.reader,
		Finalizer: finalizer,
		Kind:      "binding",
		Workloads: func(obj *profilebindingapi.ProfileBinding) *[]string { return &obj.Status.ActiveWorkloads },
		Users:     r.bindingUsers,
	}
}

// trackPod adds the pod to the active workloads of the binding and ensures
// the finalizer.
func (r *BindingTrackerReconciler) trackPod(
	ctx context.Context, binding *profilebindingapi.ProfileBinding, podID string,
) error {
	return r.tracker().Track(ctx, binding, podID)
}

// untrackPod removes the pod from the active workloads of the binding and
// drops the finalizer once no workload is left.
func (r *BindingTrackerReconciler) untrackPod(
	ctx context.Context, binding *profilebindingapi.ProfileBinding, podID string,
) error {
	return r.tracker().Untrack(ctx, binding, podID)
}

// bindingEnabled returns whether the binding webhook mutates the pods of the
// namespace of the pod, see podAnnotatedWithBinding. It is only looked up if
// needsNamespaceCheck, the others do not need it.
func (r *BindingTrackerReconciler) bindingEnabled(
	ctx context.Context, pod *corev1.Pod,
) (bool, error) {
	if !needsNamespaceCheck(pod) {
		return true, nil
	}

	return r.namespaceBindingEnabled(ctx, pod.Namespace)
}

// needsNamespaceCheck returns true for a pod with ephemeral containers and
// without the applied bindings annotation, whose bindings depend on whether
// the binding webhook selects its namespace.
func needsNamespaceCheck(pod *corev1.Pod) bool {
	_, ok := pod.GetAnnotations()[profilebindingapi.AppliedBindingsAnnotation]

	return !ok && len(pod.Spec.EphemeralContainers) > 0
}

// namespaceBindingEnabled returns whether the binding webhook mutates the pods
// of the namespace.
func (r *BindingTrackerReconciler) namespaceBindingEnabled(
	ctx context.Context, namespace string,
) (bool, error) {
	enabled, err := bindata.WebhookSelectsNamespace(
		ctx, r.client, bindata.BindingWebhookName, namespace,
	)
	if err != nil {
		return false, fmt.Errorf("checking whether binding is enabled: %w", err)
	}

	return enabled, nil
}

// podAnnotatedWithBinding returns true if the binding webhook applied the
// binding to the pod, which it records in an annotation of the pod. Pods
// created before the webhook set the annotation stay tracked while they match
// the binding, but do not get tracked anew, because matching the binding does
// not mean that the webhook applied it, for example in a namespace without
// binding enabled. bindingEnabled tells whether the binding webhook mutates
// the pods of the namespace of the pod.
func podAnnotatedWithBinding(
	pb *profilebindingapi.ProfileBinding, pod *corev1.Pod, tracked, bindingEnabled bool,
) bool {
	applied, ok := pod.GetAnnotations()[profilebindingapi.AppliedBindingsAnnotation]
	if ok && slices.Contains(strings.Split(applied, ","), pb.GetName()) {
		return true
	}

	if !ok && tracked && podMatchesBinding(pb, pod) {
		return true
	}

	// The annotation cannot be changed when ephemeral containers get added,
	// so the bindings the webhook applied to them are not listed. A pod which
	// got no binding applied on creation has no annotation at all, like the
	// pods of a namespace without binding enabled, whose ephemeral
	// containers the webhook does not bind either.
	return (ok || bindingEnabled) &&
		podMatchesSelector(pb, labels.Set(pod.GetLabels())) &&
		ephemeralContainersUseImage(pb, pod)
}

// podMatchesBinding returns true if the binding webhook applies the binding to
// the pod: the pod labels match the selector and a container uses the image.
func podMatchesBinding(pb *profilebindingapi.ProfileBinding, pod *corev1.Pod) bool {
	return podMatchesSelector(pb, labels.Set(pod.GetLabels())) && podUsesImage(pb, pod)
}

func podMatchesSelector(
	pb *profilebindingapi.ProfileBinding,
	podLabels labels.Set,
) bool {
	if pb.Spec.PodSelector == nil {
		return true
	}

	selector, err := metav1.LabelSelectorAsSelector(pb.Spec.PodSelector)
	if err != nil {
		return false
	}

	return selector.Matches(podLabels)
}

// podUsesImage returns true if a container of the pod uses the image of the
// binding. The images get compared like the binding webhook does, so a binding
// for nginx matches a container using docker.io/library/nginx:latest.
func podUsesImage(pb *profilebindingapi.ProfileBinding, pod *corev1.Pod) bool {
	if pb.Spec.Image == profilebindingapi.SelectAllContainersImage {
		return true
	}

	for i := range pod.Spec.Containers {
		if util.SameImage(pod.Spec.Containers[i].Image, pb.Spec.Image) {
			return true
		}
	}

	for i := range pod.Spec.InitContainers {
		if util.SameImage(pod.Spec.InitContainers[i].Image, pb.Spec.Image) {
			return true
		}
	}

	return ephemeralContainersUseImage(pb, pod)
}

func ephemeralContainersUseImage(pb *profilebindingapi.ProfileBinding, pod *corev1.Pod) bool {
	for i := range pod.Spec.EphemeralContainers {
		if pb.Spec.Image == profilebindingapi.SelectAllContainersImage ||
			util.SameImage(pod.Spec.EphemeralContainers[i].Image, pb.Spec.Image) {
			return true
		}
	}

	return false
}

// profileCarrier returns a function which tells whether the pod or one of its
// containers uses the profile of the binding like the binding webhook sets
// it. A profile which does not exist, or has no status, cannot have been
// applied, so no pod carries it.
func (r *BindingTrackerReconciler) profileCarrier(
	ctx context.Context, pb *profilebindingapi.ProfileBinding,
) (func(*corev1.Pod) bool, error) {
	none := func(*corev1.Pod) bool { return false }
	key := util.NamespacedName(pb.Spec.ProfileRef.Name, "")

	var carries func(seccomp *corev1.SeccompProfile, selinux *corev1.SELinuxOptions,
		apparmor *corev1.AppArmorProfile) bool

	switch pb.Spec.ProfileRef.Kind {
	case profilebindingapi.ProfileBindingKindSeccompProfile:
		profile := &seccompprofileapi.SeccompProfile{}
		if found, err := r.getProfile(ctx, key, profile); err != nil || !found {
			return none, err
		}

		localhost := profile.Status.LocalhostProfile
		if localhost == "" {
			return none, nil
		}

		carries = func(seccomp *corev1.SeccompProfile, _ *corev1.SELinuxOptions, _ *corev1.AppArmorProfile) bool {
			return seccomp != nil && seccomp.Type == corev1.SeccompProfileTypeLocalhost &&
				ptr.Deref(seccomp.LocalhostProfile, "") == localhost
		}
	case profilebindingapi.ProfileBindingKindSelinuxProfile:
		profile := &selinuxprofileapi.SelinuxProfile{}
		if found, err := r.getProfile(ctx, key, profile); err != nil || !found {
			return none, err
		}

		usage := profile.Status.Usage
		if usage == "" {
			return none, nil
		}

		carries = func(_ *corev1.SeccompProfile, selinux *corev1.SELinuxOptions, _ *corev1.AppArmorProfile) bool {
			return selinux != nil && selinux.Type == usage
		}
	case profilebindingapi.ProfileBindingKindAppArmorProfile:
		profile := &apparmorprofileapi.AppArmorProfile{}
		if found, err := r.getProfile(ctx, key, profile); err != nil || !found {
			return none, err
		}

		name := profile.GetProfileName()
		carries = func(_ *corev1.SeccompProfile, _ *corev1.SELinuxOptions, apparmor *corev1.AppArmorProfile) bool {
			return apparmor != nil && apparmor.Type == corev1.AppArmorProfileTypeLocalhost &&
				ptr.Deref(apparmor.LocalhostProfile, "") == name
		}
	default:
		return none, nil
	}

	return func(pod *corev1.Pod) bool {
		for fields := range util.SecurityContextProfiles(pod) {
			if carries(fields.Seccomp, fields.SELinux, fields.AppArmor) {
				return true
			}
		}

		return false
	}, nil
}

// getProfile reads the profile of the key from the cache, without copying
// it, as it is only read. It returns false if the profile does not exist or
// has no status, like a profile which the binding webhook does not apply.
func (r *BindingTrackerReconciler) getProfile(
	ctx context.Context, key client.ObjectKey, profile profilebasev1.StatusBaseUser,
) (bool, error) {
	if err := r.client.Get(ctx, key, profile, client.UnsafeDisableDeepCopy); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}

		return false, fmt.Errorf("getting profile %s: %w", key.Name, err)
	}

	return profile.GetStatusBase().Status != "", nil
}
