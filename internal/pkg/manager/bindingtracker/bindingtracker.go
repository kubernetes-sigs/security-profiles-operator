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
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
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

func (r *BindingTrackerReconciler) Healthz(*http.Request) error {
	return nil
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
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
		uses := !util.PodCompleted(pod) && podUsesBinding(binding, pod, tracked, bindingEnabled)

		// A binding which is being deleted must not track new pods: the API
		// server rejects adding finalizers to it.
		if uses && binding.GetDeletionTimestamp().IsZero() {
			// The cached binding tells if the pod is tracked already, so a
			// pod update does not cost an API read per binding.
			if tracked && controllerutil.ContainsFinalizer(binding, finalizer) {
				continue
			}

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

// tracker tracks the pods in the active workloads of the bindings.
func (r *BindingTrackerReconciler) tracker() *workloadtracker.Tracker[*profilebindingapi.ProfileBinding] {
	return &workloadtracker.Tracker[*profilebindingapi.ProfileBinding]{
		Client:    r.client,
		Reader:    r.reader,
		Finalizer: finalizer,
		Kind:      "binding",
		Workloads: func(obj *profilebindingapi.ProfileBinding) *[]string { return &obj.Status.ActiveWorkloads },
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
// namespace of the pod, see podUsesBinding. It is only looked up for a pod
// with ephemeral containers and without the applied bindings annotation, the
// others do not need it.
func (r *BindingTrackerReconciler) bindingEnabled(
	ctx context.Context, pod *corev1.Pod,
) (bool, error) {
	if _, ok := pod.GetAnnotations()[profilebindingapi.AppliedBindingsAnnotation]; ok ||
		len(pod.Spec.EphemeralContainers) == 0 {
		return true, nil
	}

	enabled, err := bindata.WebhookSelectsNamespace(
		ctx, r.client, bindata.BindingWebhookName, pod.Namespace,
	)
	if err != nil {
		return false, fmt.Errorf("checking whether binding is enabled: %w", err)
	}

	return enabled, nil
}

// podUsesBinding returns true if the binding webhook applied the binding to
// the pod, which it records in an annotation of the pod. Pods created before
// the webhook set the annotation stay tracked while they match the binding,
// but do not get tracked anew, because matching the binding does not mean that
// the webhook applied it, for example in a namespace without binding enabled.
// bindingEnabled tells whether the binding webhook mutates the pods of the
// namespace of the pod.
func podUsesBinding(
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
