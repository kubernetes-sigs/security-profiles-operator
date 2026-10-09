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
	"maps"
	"reflect"
	"slices"
	"strings"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func (r *RecordingTrackerReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "recording-tracker"

	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(name)

	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&profilerecordingapi.ProfileRecording{},
		linkedPodsKey,
		func(rawObj client.Object) []string {
			pr, ok := rawObj.(*profilerecordingapi.ProfileRecording)
			if !ok {
				return []string{}
			}

			return pr.Status.ActiveWorkloads
		},
	); err != nil {
		return fmt.Errorf("creating profile recording index: %w", err)
	}

	if err := r.setupStatus(mgr, name+"-status"); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(controller.Options(ctx)).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: func(_ event.CreateEvent) bool { return true },
			DeleteFunc: func(_ event.DeleteEvent) bool { return true },
			// The recording webhook annotates the pods it records, also
			// on updates. A completed pod is not recorded anymore.
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels()) ||
					!reflect.DeepEqual(
						e.ObjectOld.GetAnnotations(),
						e.ObjectNew.GetAnnotations(),
					) ||
					util.PodCompletedNow(e.ObjectOld, e.ObjectNew)
			},
			GenericFunc: func(_ event.GenericEvent) bool { return true },
		})).
		// Reconcile the tracked pods once a recording enters the cache, for
		// example after an operator restart. Pods deleted while no delete event
		// could be observed are then released from the recording.
		Watches(
			&profilerecordingapi.ProfileRecording{},
			handler.EnqueueRequestsFromMapFunc(activeWorkloadRequests),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return true },
				DeleteFunc:  func(event.DeleteEvent) bool { return false },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			}),
		).
		Complete(r)
}

// activeWorkloadRequests maps a recording to reconcile requests for the pods
// it tracks.
func activeWorkloadRequests(_ context.Context, obj client.Object) []reconcile.Request {
	recording, ok := obj.(*profilerecordingapi.ProfileRecording)
	if !ok {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(recording.Status.ActiveWorkloads))
	for _, podName := range recording.Status.ActiveWorkloads {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: podName, Namespace: recording.Namespace},
		})
	}

	return requests
}

// setupStatus adds the controller of the recording conditions. They depend
// on the SPODs, the recording webhook, the namespace of the recording and the
// profiles which the recording would write, so changes of those reconcile
// the recordings again.
func (r *RecordingTrackerReconciler) setupStatus(mgr ctrl.Manager, name string) error {
	// The SPOD controller registers the SPOD kind as well, but the conditions
	// do not depend on it being enabled.
	if err := spodapi.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("adding the SPOD API to the scheme: %w", err)
	}

	operatorNamespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		r.log.Info("Not checking the recorders of the recordings", "reason", err.Error())
	}

	status := &recordingStatusReconciler{
		client:            r.client,
		reader:            r.reader,
		log:               r.log.WithName("status"),
		operatorNamespace: operatorNamespace,
		env:               recorderEnvFromEnvironment(),
	}

	b := ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&profilerecordingapi.ProfileRecording{}, builder.WithPredicates(
			recordingStatusPredicate(),
		)).
		// The daemons only follow the SPOD named spod.
		Watches(
			&spodapi.SecurityProfilesOperatorDaemon{},
			handler.EnqueueRequestsFromMapFunc(status.allRecordings),
			builder.WithPredicates(
				predicate.GenerationChangedPredicate{},
				predicate.NewPredicateFuncs(func(obj client.Object) bool {
					return obj.GetName() == config.SPOdName
				}),
			),
		).
		// The manager caches the webhook configuration by name.
		Watches(
			&admissionregv1.MutatingWebhookConfiguration{},
			handler.EnqueueRequestsFromMapFunc(status.allRecordings),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return obj.GetName() == bindata.MutatingWebhookConfigName
			})),
		).
		Watches(
			&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(status.recordingsInNamespace),
			builder.OnlyMetadata,
			builder.WithPredicates(labelsChanged()),
		)

	for kind, k := range profileKinds {
		b = b.Watches(
			k.newObject(),
			handler.EnqueueRequestsFromMapFunc(status.recordingsWritingProfile(kind)),
			builder.WithPredicates(profileOwnerEventsPredicate()),
		)
	}

	if err := b.Complete(status); err != nil {
		return fmt.Errorf("creating recording status controller: %w", err)
	}

	return nil
}

// recordingStatusPredicate passes the changes of a recording which its
// conditions depend on: its spec and the pods it tracks, whose containers
// tell the profiles it writes.
func recordingStatusPredicate() predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldRecording, okOld := e.ObjectOld.(*profilerecordingapi.ProfileRecording)
			newRecording, okNew := e.ObjectNew.(*profilerecordingapi.ProfileRecording)

			if !okOld || !okNew {
				return true
			}

			return oldRecording.GetGeneration() != newRecording.GetGeneration() ||
				!slices.Equal(
					oldRecording.Status.ActiveWorkloads,
					newRecording.Status.ActiveWorkloads,
				)
		},
	}
}

// labelsChanged passes the label changes of existing objects.
func labelsChanged() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// profileOwnerEventsPredicate passes the events which can change whether a
// profile belongs to a recording: its creation, its deletion and changes of
// its labels.
func profileOwnerEventsPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// listRecordings returns reconcile requests for the cached recordings which
// pass the filter. A failing list is logged, as a map function cannot return
// an error.
func (r *recordingStatusReconciler) listRecordings(
	ctx context.Context,
	filter func(*profilerecordingapi.ProfileRecording) bool,
	opts ...client.ListOption,
) []reconcile.Request {
	recordings := &profilerecordingapi.ProfileRecordingList{}
	if err := r.client.List(ctx, recordings, opts...); err != nil {
		r.log.Error(err, "Cannot list recordings")

		return nil
	}

	var requests []reconcile.Request

	for i := range recordings.Items {
		recording := &recordings.Items[i]
		if filter(recording) {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(recording),
			})
		}
	}

	return requests
}

// allRecordings maps an object to reconcile requests for all recordings.
func (r *recordingStatusReconciler) allRecordings(
	ctx context.Context, _ client.Object,
) []reconcile.Request {
	return r.listRecordings(ctx, func(*profilerecordingapi.ProfileRecording) bool { return true })
}

// recordingsInNamespace maps a namespace to reconcile requests for its
// recordings.
func (r *recordingStatusReconciler) recordingsInNamespace(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	return r.listRecordings(
		ctx,
		func(*profilerecordingapi.ProfileRecording) bool { return true },
		client.InNamespace(obj.GetName()),
	)
}

// recordingsWritingProfile returns a function which maps a profile of the
// kind to reconcile requests for the recordings of the kind which may write
// it. Their names prefix the profile name.
func (r *recordingStatusReconciler) recordingsWritingProfile(
	kind profilerecordingapi.ProfileRecordingKind,
) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		return r.listRecordings(ctx, func(recording *profilerecordingapi.ProfileRecording) bool {
			return recording.Spec.Kind == kind &&
				strings.HasPrefix(obj.GetName(), recording.GetName()+"-")
		})
	}
}
