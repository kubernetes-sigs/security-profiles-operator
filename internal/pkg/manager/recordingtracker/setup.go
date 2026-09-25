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
	"reflect"

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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
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

	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name+"-status").
		For(&profilerecordingapi.ProfileRecording{}, builder.WithPredicates(
			predicate.GenerationChangedPredicate{},
		)).
		Complete(&recordingStatusReconciler{
			client: r.client,
			reader: r.reader,
			log:    r.log.WithName("status"),
		}); err != nil {
		return fmt.Errorf("creating recording status controller: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: func(_ event.CreateEvent) bool { return true },
			DeleteFunc: func(_ event.DeleteEvent) bool { return true },
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
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
