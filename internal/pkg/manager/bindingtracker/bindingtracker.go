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
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
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

func (r *BindingTrackerReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return profilebindingapi.SchemeBuilder
}

func (r *BindingTrackerReconciler) Healthz(*http.Request) error {
	return nil
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilebindings/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

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
	if util.IgnoreNotFound(err) != nil {
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

	for i := range bindings.Items {
		binding := &bindings.Items[i]

		// A binding which is being deleted must not track new pods: the API
		// server rejects adding finalizers to it.
		if podMatchesBinding(binding, pod) && binding.GetDeletionTimestamp().IsZero() {
			logger.Info("Tracking pod in binding", "binding", binding.Name)

			if err := r.trackPod(ctx, binding, podID); err != nil {
				return reconcile.Result{}, err
			}

			continue
		}

		if slices.Contains(binding.Status.ActiveWorkloads, podID) &&
			!podMatchesBinding(binding, pod) {
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

// trackPod adds the pod to the active workloads of the binding and ensures
// the finalizer.
func (r *BindingTrackerReconciler) trackPod(
	ctx context.Context, binding *profilebindingapi.ProfileBinding, podID string,
) error {
	if err := util.Retry(func() error {
		if err := r.reader.Get(
			ctx, util.NamespacedName(binding.GetName(), binding.GetNamespace()), binding,
		); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}

			return fmt.Errorf("retrieving binding: %w", err)
		}

		updated := appendIfNotExists(binding.Status.ActiveWorkloads, podID)
		if len(updated) == len(binding.Status.ActiveWorkloads) {
			return nil
		}

		binding.Status.ActiveWorkloads = updated

		if err := r.client.Status().Update(ctx, binding); err != nil {
			return fmt.Errorf("updating binding status: %w", err)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating binding status: %w", err)
	}

	if err := util.Retry(func() error {
		return client.IgnoreNotFound(
			util.AddFinalizer(ctx, r.client, binding, finalizer),
		)
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("adding finalizer: %w", err)
	}

	return nil
}

// untrackPod removes the pod from the active workloads of the binding and
// drops the finalizer once no workload is left.
func (r *BindingTrackerReconciler) untrackPod(
	ctx context.Context, binding *profilebindingapi.ProfileBinding, podID string,
) error {
	if err := util.Retry(func() error {
		if err := r.reader.Get(
			ctx, util.NamespacedName(binding.GetName(), binding.GetNamespace()), binding,
		); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}

			return fmt.Errorf("retrieving binding: %w", err)
		}

		updated := removeIfExists(binding.Status.ActiveWorkloads, podID)
		if len(updated) == len(binding.Status.ActiveWorkloads) {
			return nil
		}

		binding.Status.ActiveWorkloads = updated

		if err := r.client.Status().Update(ctx, binding); err != nil {
			return fmt.Errorf("updating binding status: %w", err)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating binding status: %w", err)
	}

	if err := util.Retry(func() error {
		if err := r.reader.Get(
			ctx, util.NamespacedName(binding.GetName(), binding.GetNamespace()), binding,
		); err != nil {
			if errors.IsNotFound(err) {
				return nil
			}

			return fmt.Errorf("retrieving binding: %w", err)
		}

		if len(binding.Status.ActiveWorkloads) == 0 {
			return client.IgnoreNotFound(
				util.RemoveFinalizer(ctx, r.client, binding, finalizer),
			)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	return nil
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

func podUsesImage(pb *profilebindingapi.ProfileBinding, pod *corev1.Pod) bool {
	if pb.Spec.Image == profilebindingapi.SelectAllContainersImage {
		return true
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Image == pb.Spec.Image {
			return true
		}
	}

	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Image == pb.Spec.Image {
			return true
		}
	}

	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Image == pb.Spec.Image {
			return true
		}
	}

	return false
}

func appendIfNotExists(list []string, item string) []string {
	if slices.Contains(list, item) {
		return list
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
