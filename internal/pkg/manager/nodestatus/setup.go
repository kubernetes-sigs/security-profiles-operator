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

package nodestatus

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Setup adds a controller that aggregates the node statuses of the profiles.
func (r *StatusReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, r.Name())

	namespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("get operator namespace: %w", err)
	}

	r.namespace = namespace

	// A spec change of a profile does not necessarily change a node status,
	// but the conditions of the profile have to report the new generation.
	// A deleted profile has no status to update.
	generationChanged := builder.WithPredicates(
		predicate.GenerationChangedPredicate{},
		predicate.Funcs{DeleteFunc: func(event.DeleteEvent) bool { return false }},
	)

	// Register a special reconciler for status events. Every status of a
	// profile leads to the same aggregated profile status, so the events of
	// all statuses of a profile are mapped to the same request, which the
	// work queue deduplicates.
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		WithOptions(controller.Options(ctx)).
		Watches(&secprofnodestatusapi.SecurityProfileNodeStatus{},
			handler.EnqueueRequestsFromMapFunc(r.siblingStatusRequests),
			builder.WithPredicates(nodeStatusChanged())).
		Watches(&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(r.statusRequests("SeccompProfile")),
			generationChanged).
		Watches(&selinuxprofileapi.SelinuxProfile{},
			handler.EnqueueRequestsFromMapFunc(r.statusRequests("SelinuxProfile")),
			generationChanged).
		Watches(&selinuxprofileapi.RawSelinuxProfile{},
			handler.EnqueueRequestsFromMapFunc(r.statusRequests("RawSelinuxProfile")),
			generationChanged).
		Watches(&apparmorapi.AppArmorProfile{},
			handler.EnqueueRequestsFromMapFunc(r.statusRequests("AppArmorProfile")),
			generationChanged).
		// The status of a deleted node is dropped from the aggregation, which
		// nothing else triggers.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.deletedNodeRequests),
			builder.OnlyMetadata,
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(event.CreateEvent) bool { return false },
				DeleteFunc:  func(event.DeleteEvent) bool { return true },
				UpdateFunc:  func(event.UpdateEvent) bool { return false },
				GenericFunc: func(event.GenericEvent) bool { return false },
			})).
		Complete(r)
}

// deletedNodeRequests maps a deleted node to the requests of the profiles
// which it has a status of.
func (r *StatusReconciler) deletedNodeRequests(
	ctx context.Context, obj client.Object,
) []reconcile.Request {
	statuses := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	// The statuses live next to their profiles.
	if err := r.client.List(ctx, statuses,
		client.MatchingLabels{
			secprofnodestatusapi.StatusToNodeLabel: util.NodeNameLabelValue(obj.GetName()),
		},
	); err != nil {
		r.log.Error(err, "Cannot list the statuses of a deleted node", "node", obj.GetName())

		return nil
	}

	// The work queue drops the duplicate requests of the statuses of a
	// profile.
	requests := make([]reconcile.Request, 0, len(statuses.Items))
	for i := range statuses.Items {
		requests = append(requests, r.siblingStatusRequests(ctx, &statuses.Items[i])...)
	}

	return requests
}

// nodeStatusChanged passes the updates of a node status which matter for the
// aggregation: the state, the node, the owner and the profile label. The daemon
// also keeps a state label and annotations on the status, whose updates would
// otherwise trigger an aggregation of their own.
func nodeStatusChanged() predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldStatus, okOld := e.ObjectOld.(*secprofnodestatusapi.SecurityProfileNodeStatus)
			newStatus, okNew := e.ObjectNew.(*secprofnodestatusapi.SecurityProfileNodeStatus)

			if !okOld || !okNew {
				return true
			}

			return oldStatus.Status != newStatus.Status ||
				oldStatus.Spec != newStatus.Spec ||
				!newStatus.DeletionTimestamp.Equal(oldStatus.DeletionTimestamp) ||
				!equality.Semantic.DeepEqual(
					oldStatus.OwnerReferences,
					newStatus.OwnerReferences,
				) ||
				oldStatus.Labels[secprofnodestatusapi.StatusToProfLabel] !=
					newStatus.Labels[secprofnodestatusapi.StatusToProfLabel]
		},
	}
}

// statusRequests returns a map function which enqueues the request of a
// profile of the provided kind. It aggregates the node statuses of the
// profile, and removes the finalizers of deleted nodes if the profile is being
// deleted, whose node statuses may be gone already.
func (r *StatusReconciler) statusRequests(kind string) handler.MapFunc {
	return func(_ context.Context, obj client.Object) []reconcile.Request {
		return []reconcile.Request{profileRequest(kind, obj.GetNamespace(), obj.GetName())}
	}
}

// siblingStatusRequests maps an event of a node status to the request of its
// profile, so that the statuses of a profile share a single request which the
// work queue deduplicates. A status which does not match its owner is
// reconciled on its own, which reports the mismatch.
func (r *StatusReconciler) siblingStatusRequests(
	_ context.Context, obj client.Object,
) []reconcile.Request {
	owner := metav1.GetControllerOf(obj)
	label := obj.GetLabels()[secprofnodestatusapi.StatusToProfLabel]

	if owner == nil || label == "" || util.KindNameDNSLengthName(owner.Kind, owner.Name) != label {
		return []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(obj)}}
	}

	return []reconcile.Request{profileRequest(owner.Kind, obj.GetNamespace(), owner.Name)}
}

// firstOwnedStatus returns the status with the lowest name which is
// controlled by the profile of the provided kind and name, or nil if there is
// none. Statuses without that owner cannot be reconciled for the profile.
func firstOwnedStatus(
	list *secprofnodestatusapi.SecurityProfileNodeStatusList, kind, name string,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	var first *secprofnodestatusapi.SecurityProfileNodeStatus

	for i := range list.Items {
		owner := metav1.GetControllerOf(&list.Items[i])
		if owner == nil || owner.Kind != kind || owner.Name != name {
			continue
		}

		if first == nil || list.Items[i].Name < first.Name {
			first = &list.Items[i]
		}
	}

	return first
}
