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

package recordingmerger

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Setup adds a controller that reconciles any profilerecordings.
func (r *PolicyMergeReconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, r.Name())

	// Deleted recordings wait until the partial profiles recorded before 1.0
	// are adopted, see legacyAdopter.
	r.legacyAdoptionPending.Store(true)

	if err := mgr.Add(&legacyAdopter{r: r}); err != nil {
		return fmt.Errorf("adding the adoption of partial profiles recorded before 1.0: %w", err)
	}

	b := ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&profilerecordingapi.ProfileRecording{}, builder.WithPredicates(
			mergePredicate(),
		))

	// A deleted recording keeps its finalizer while partial profiles are
	// left, for example ones which could not be merged. It gets released once
	// they are gone.
	for _, obj := range []client.Object{
		&seccompprofileapi.SeccompProfile{},
		&selinuxprofileapi.SelinuxProfile{},
		&apparmorprofileapi.AppArmorProfile{},
	} {
		b = b.Watches(
			obj,
			handler.EnqueueRequestsFromMapFunc(recordingOfPartialProfile),
			builder.WithPredicates(partialProfileDeletedPredicate()),
		)
	}

	return b.Complete(r)
}

// recordingOfPartialProfile returns the recording of a partial profile.
func recordingOfPartialProfile(_ context.Context, obj client.Object) []reconcile.Request {
	name := obj.GetLabels()[profilerecordingapi.ProfileToRecordingLabel]
	namespace := obj.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel]

	if name == "" || namespace == "" {
		return nil
	}

	return []reconcile.Request{{NamespacedName: types.NamespacedName{
		Name: name, Namespace: namespace,
	}}}
}

// partialProfileDeletedPredicate passes the deletions of partial profiles.
func partialProfileDeletedPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return false },
		UpdateFunc: func(event.UpdateEvent) bool { return false },
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, partial := e.Object.GetLabels()[profilebase.ProfilePartialLabel]

			return partial
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// mergePredicate selects the events the merger needs. Only a deletion is of
// interest, and because the recording carries the has-unmerged-profiles
// finalizer that deletion arrives as an update setting the deletion timestamp.
// The delete event only fires once the finalizer is gone, which is what this
// controller is responsible for removing, so filtering updates out would leave
// every recording stuck in Terminating with its profiles never merged.
// A recording which is already being deleted when the manager starts only
// arrives as a create event, which must pass for the same reason.
func mergePredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object != nil && !e.Object.GetDeletionTimestamp().IsZero()
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew != nil && !e.ObjectNew.GetDeletionTimestamp().IsZero()
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}
