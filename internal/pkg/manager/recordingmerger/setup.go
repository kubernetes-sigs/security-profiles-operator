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
	"maps"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Setup adds a controller that reconciles any profilerecordings.
func (r *PolicyMergeReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, r.Name())

	// A recording outside of the namespaces of a restricted cache may have
	// recorded a profile as well, see checkLegacyOwner, so they are listed
	// from the API server then.
	r.recordingReader = r.client
	if config.WatchNamespaces() != "" {
		r.recordingReader = r.reader
	}

	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &profilerecordingapi.ProfileRecording{}, recordingNameKey, recordingNameIndex,
	); err != nil {
		return fmt.Errorf("creating profile recording name index: %w", err)
	}

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
	// they are gone. A partial profile which a node stored after the merge
	// gets merged once it shows up.
	for _, obj := range []client.Object{
		&seccompprofileapi.SeccompProfile{},
		&selinuxprofileapi.SelinuxProfile{},
		&apparmorprofileapi.AppArmorProfile{},
	} {
		b = b.Watches(
			obj,
			handler.EnqueueRequestsFromMapFunc(recordingOfPartialProfile),
			builder.WithPredicates(partialProfileEventsPredicate()),
		)

		// A deleted recording whose merge is blocked by a profile of
		// somebody else gets merged once that profile is deleted or labeled
		// for it.
		b = b.Watches(
			obj,
			handler.EnqueueRequestsFromMapFunc(r.recordingsBlockedBy),
			builder.WithPredicates(blockingProfileEventsPredicate()),
		)
	}

	return b.Complete(r)
}

// blockingProfileEventsPredicate passes the deletions and label changes of
// profiles which are not partial, which can unblock the merge of a deleted
// recording.
func blockingProfileEventsPredicate() predicate.Funcs {
	isPartial := func(obj client.Object) bool {
		_, partial := obj.GetLabels()[profilebase.ProfilePartialLabel]

		return partial
	}

	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return !isPartial(e.ObjectNew) &&
				!maps.Equal(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
		},
		DeleteFunc:  func(e event.DeleteEvent) bool { return !isPartial(e.Object) },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// recordingsBlockedBy maps a profile to the deleted recordings which wait for
// their partial profiles to be merged and whose merged profiles it may be:
// their names prefix its name.
func (r *PolicyMergeReconciler) recordingsBlockedBy(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	recordings := &profilerecordingapi.ProfileRecordingList{}
	if err := r.client.List(ctx, recordings); err != nil {
		r.log.Error(err, "Cannot list recordings blocked by profile", "profile", obj.GetName())

		return nil
	}

	var requests []reconcile.Request

	for i := range recordings.Items {
		recording := &recordings.Items[i]

		if recording.GetDeletionTimestamp().IsZero() ||
			!controllerutil.ContainsFinalizer(
				recording,
				profilerecordingapi.RecordingHasUnmergedProfiles,
			) ||
			!strings.HasPrefix(obj.GetName(), recording.GetName()+"-") {
			continue
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(recording),
		})
	}

	return requests
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

// partialProfileEventsPredicate passes the creations and deletions of partial
// profiles.
func partialProfileEventsPredicate() predicate.Funcs {
	isPartial := func(obj client.Object) bool {
		_, partial := obj.GetLabels()[profilebase.ProfilePartialLabel]

		return partial
	}

	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return isPartial(e.Object) },
		UpdateFunc:  func(event.UpdateEvent) bool { return false },
		DeleteFunc:  func(e event.DeleteEvent) bool { return isPartial(e.Object) },
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
