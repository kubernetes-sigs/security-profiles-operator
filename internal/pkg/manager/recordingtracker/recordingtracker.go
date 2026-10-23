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
	"slices"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadtracker"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	linkedPodsKey    = ".metadata.recordingActiveWorkloads"
	finalizer        = "active-seccomp-profile-recording-lock"
	reconcileTimeout = 1 * time.Minute

	// recordingAnnotationsKey indexes the pods by the recordings which
	// their recording annotations name.
	recordingAnnotationsKey = ".metadata.annotations.recordings"
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

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//
// The Ready condition of a recording tells whether the SPODs enable its
// recorder and whether the recording webhook selects its namespace.
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,namespace=security-profiles-operator,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,resourceNames=spo-mutating-webhook-configuration,verbs=get;list;watch
//
// The ProfileConflict condition of a recording names the profiles it would
// write, but which belong to somebody else.
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles;selinuxprofiles;apparmorprofiles,verbs=get;list;watch

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
	if client.IgnoreNotFound(err) != nil {
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

		if err := r.untrackPod(ctx, recording, podName); err != nil {
			return reconcile.Result{}, fmt.Errorf("untracking deleted pod: %w", err)
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

	for i := range recordings.Items {
		recording := &recordings.Items[i]

		tracked := slices.Contains(recording.Status.ActiveWorkloads, podName)

		// Only the pods which the recording webhook annotated get recorded,
		// see podRecordedBy. A pod which matches the selector without the
		// annotations, for example because it got created before the
		// recording, is not. A recorded pod stays recorded until it
		// completes, like the pod of a finished Job, whose profiles the
		// recorder collects then.
		if util.PodCompleted(pod) || !podRecordedBy(pod, recording, tracked) {
			if tracked {
				logger.Info("Removing pod which is not recorded", "recording", recording.Name)

				if err := r.untrackPod(ctx, recording, podName); err != nil {
					return reconcile.Result{}, fmt.Errorf("untracking pod: %w", err)
				}
			}

			continue
		}

		// The API server rejects adding finalizers to an object which is
		// being deleted, so retrying would never succeed.
		if !recording.GetDeletionTimestamp().IsZero() {
			continue
		}

		// The cached recording tells if the pod is tracked already, so a
		// pod update does not cost an API read per recording.
		if podTracked(recording, podName) {
			continue
		}

		logger.Info("Tracking pod in recording", "recording", recording.Name)

		if err := r.trackPod(ctx, recording, podName); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

// podTracked returns true if the recording lists the pod as active workload
// and carries the finalizer, so that tracking it again would change nothing.
func podTracked(recording *profilerecordingapi.ProfileRecording, podName string) bool {
	return slices.Contains(recording.Status.ActiveWorkloads, podName) &&
		controllerutil.ContainsFinalizer(recording, finalizer)
}

// podRecordedBy returns true if the recording records a container of the pod.
// Like the profile recorder of the daemon, which checks the recording when the
// container starts, a tracked pod stays recorded while it carries an
// annotation of the recording, also if its labels or the recording changed
// since. A pod gets tracked anew if the recording webhook annotated it for
// the recording while it admitted the pod, also if the recording changed
// since, see annotatedContainers. Otherwise the recording has to select the
// pod and the annotated container now, see recordedContainers, like the
// daemon checks it for a running pod which it sees for the first time. A pod
// author can add an annotation after the creation of the pod, which the
// recording webhook does not check. This is no security boundary, as whoever
// can annotate the pod can relabel it as well. It keeps a recording from
// tracking the pods which it does not record.
func podRecordedBy(
	pod *corev1.Pod, recording *profilerecordingapi.ProfileRecording, tracked bool,
) bool {
	if tracked {
		return len(annotatedContainers(pod, recording.GetName(), false)) > 0
	}

	return len(annotatedContainers(pod, recording.GetName(), true)) > 0 ||
		len(recordedContainers(pod, recording)) > 0
}

// recordingUsers returns the names of the pods which are recorded by the
// recording, which fill up an emptied list of active workloads, see
// workloadtracker.Tracker. They get checked like pods tracked anew, as the pod
// author can add the annotations of the recording, which would otherwise keep
// the recording from being deleted. A pod which the webhook annotated at its
// admission counts, also if the recording or the labels of the pod changed
// since.
func (r *RecordingTrackerReconciler) recordingUsers(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording,
) ([]string, error) {
	// The pods are only read, so the cached ones are not copied.
	pods := &corev1.PodList{}
	if err := r.client.List(
		ctx, pods, client.InNamespace(recording.Namespace), client.UnsafeDisableDeepCopy,
	); err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	var users []string

	for i := range pods.Items {
		if pod := &pods.Items[i]; !util.PodCompleted(pod) && podRecordedBy(pod, recording, false) {
			users = append(users, pod.Name)
		}
	}

	return users, nil
}

// tracker tracks the pods in the active workloads of the recordings.
func (r *RecordingTrackerReconciler) tracker() *workloadtracker.Tracker[*profilerecordingapi.ProfileRecording] {
	return &workloadtracker.Tracker[*profilerecordingapi.ProfileRecording]{
		Client:    r.client,
		Reader:    r.reader,
		Finalizer: finalizer,
		Kind:      "recording",
		Workloads: func(obj *profilerecordingapi.ProfileRecording) *[]string { return &obj.Status.ActiveWorkloads },
		Users:     r.recordingUsers,
	}
}

// trackPod adds the pod to the active workloads of the recording and ensures
// the finalizer.
func (r *RecordingTrackerReconciler) trackPod(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording, podName string,
) error {
	return r.tracker().Track(ctx, recording, podName)
}

// untrackPod removes the pod from the active workloads of the recording and
// drops the finalizer once no workload is left.
func (r *RecordingTrackerReconciler) untrackPod(
	ctx context.Context, recording *profilerecordingapi.ProfileRecording, podName string,
) error {
	return r.tracker().Untrack(ctx, recording, podName)
}
