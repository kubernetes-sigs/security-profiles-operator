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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *StatusReconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, r.Name())

	// A spec change of a profile does not necessarily change a node status,
	// but the conditions of the profile have to report the new generation.
	// A deleted profile has no status to update.
	generationChanged := builder.WithPredicates(
		predicate.GenerationChangedPredicate{},
		predicate.Funcs{DeleteFunc: func(event.DeleteEvent) bool { return false }},
	)

	// Register a special reconciler for status events
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&secprofnodestatusapi.SecurityProfileNodeStatus{}).
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
		Complete(r)
}

// statusRequests returns a map function which enqueues one node status of a
// profile of the provided kind. Every node status leads to the same aggregated
// profile status, so one is enough.
func (r *StatusReconciler) statusRequests(kind string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		list, err := listStatusesForProfile(
			ctx, r.client, obj.GetNamespace(), util.KindNameDNSLengthName(kind, obj.GetName()),
		)
		if err != nil {
			r.log.Error(err, "cannot list node statuses of profile", "profile", obj.GetName())

			return nil
		}

		if len(list.Items) == 0 {
			return nil
		}

		return []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(&list.Items[0])}}
	}
}
