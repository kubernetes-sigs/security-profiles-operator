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

package recordingtracker

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

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	linkedPodsKey    = ".metadata.recordingActiveWorkloads"
	finalizer        = "active-seccomp-profile-recording-lock"
	reconcileTimeout = 1 * time.Minute
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &RecordingTrackerReconciler{}
}

// RecordingTrackerReconciler watches Pods and updates ProfileRecording
// status.ActiveWorkloads and finalizers accordingly.
type RecordingTrackerReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
}

func (r *RecordingTrackerReconciler) Name() string {
	return "recording-tracker"
}

func (r *RecordingTrackerReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return profilerecordingapi.SchemeBuilder
}

func (r *RecordingTrackerReconciler) Healthz(*http.Request) error {
	return nil
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

func (r *RecordingTrackerReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	podName := req.Name
	pod := &corev1.Pod{}

	err := r.client.Get(ctx, req.NamespacedName, pod)
	if util.IgnoreNotFound(err) != nil {
		return reconcile.Result{}, fmt.Errorf("getting pod: %w", err)
	}

	if errors.IsNotFound(err) {
		return r.handlePodDeletion(ctx, logger, req.Namespace, podName)
	}

	return r.handlePodCreateOrUpdate(ctx, logger, pod, podName)
}

func (r *RecordingTrackerReconciler) handlePodDeletion(
	ctx context.Context,
	logger logr.Logger,
	namespace, podName string,
) (reconcile.Result, error) {
	recordings := &profilerecordingapi.ProfileRecordingList{}
	if err := r.client.List(
		ctx, recordings,
		client.MatchingFields{linkedPodsKey: podName},
		client.InNamespace(namespace),
	); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing recordings for deleted pod: %w", err)
	}

	for i := range recordings.Items {
		recording := &recordings.Items[i]
		logger.Info("Removing deleted pod from recording", "recording", recording.Name)

		if err := util.Retry(func() error {
			if err := r.reader.Get(
				ctx, util.NamespacedName(recording.GetName(), recording.GetNamespace()), recording,
			); err != nil {
				if errors.IsNotFound(err) {
					return nil
				}

				return fmt.Errorf("retrieving recording: %w", err)
			}

			updated := removeIfExists(recording.Status.ActiveWorkloads, podName)
			if len(updated) == len(recording.Status.ActiveWorkloads) {
				return nil
			}

			recording.Status.ActiveWorkloads = updated

			if err := r.client.Status().Update(ctx, recording); err != nil {
				return fmt.Errorf("updating recording status: %w", err)
			}

			return nil
		}, util.IsNotFoundOrConflict); err != nil {
			return reconcile.Result{},
				fmt.Errorf("updating recording status for deleted pod: %w", err)
		}

		if err := util.Retry(func() error {
			if err := r.reader.Get(
				ctx, util.NamespacedName(recording.GetName(), recording.GetNamespace()), recording,
			); err != nil {
				if errors.IsNotFound(err) {
					return nil
				}

				return fmt.Errorf("retrieving recording: %w", err)
			}

			if len(recording.Status.ActiveWorkloads) == 0 {
				return client.IgnoreNotFound(
					util.RemoveFinalizer(ctx, r.client, recording, finalizer),
				)
			}

			return nil
		}, util.IsNotFoundOrConflict); err != nil {
			return reconcile.Result{}, fmt.Errorf("removing finalizer for deleted pod: %w", err)
		}
	}

	return reconcile.Result{}, nil
}

func (r *RecordingTrackerReconciler) handlePodCreateOrUpdate(
	ctx context.Context,
	logger logr.Logger,
	pod *corev1.Pod,
	podName string,
) (reconcile.Result, error) {
	recordings := &profilerecordingapi.ProfileRecordingList{}
	if err := r.client.List(ctx, recordings, client.InNamespace(pod.Namespace)); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing recordings: %w", err)
	}

	podLabels := labels.Set(pod.GetLabels())

	for i := range recordings.Items {
		recording := &recordings.Items[i]

		selector, err := metav1.LabelSelectorAsSelector(recording.Spec.PodSelector)
		if err != nil {
			logger.Error(err, "invalid podSelector", "recording", recording.Name)

			continue
		}

		if !selector.Matches(podLabels) {
			continue
		}

		logger.Info("Tracking pod in recording", "recording", recording.Name)

		if err := util.Retry(func() error {
			if err := r.reader.Get(
				ctx, util.NamespacedName(recording.GetName(), recording.GetNamespace()), recording,
			); err != nil {
				if errors.IsNotFound(err) {
					return nil
				}

				return fmt.Errorf("retrieving recording: %w", err)
			}

			updated := appendIfNotExists(recording.Status.ActiveWorkloads, podName)
			if len(updated) == len(recording.Status.ActiveWorkloads) {
				return nil
			}

			recording.Status.ActiveWorkloads = updated

			if err := r.client.Status().Update(ctx, recording); err != nil {
				return fmt.Errorf("updating recording status: %w", err)
			}

			return nil
		}, util.IsNotFoundOrConflict); err != nil {
			return reconcile.Result{}, fmt.Errorf("updating recording status: %w", err)
		}

		if err := util.Retry(func() error {
			return client.IgnoreNotFound(
				util.AddFinalizer(ctx, r.client, recording, finalizer),
			)
		}, util.IsNotFoundOrConflict); err != nil {
			return reconcile.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	return reconcile.Result{}, nil
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
