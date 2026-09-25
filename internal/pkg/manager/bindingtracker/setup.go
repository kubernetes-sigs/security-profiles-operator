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
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

func (r *BindingTrackerReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "binding-tracker"

	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(name)

	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&profilebindingapi.ProfileBinding{},
		linkedPodsKey,
		func(rawObj client.Object) []string {
			pb, ok := rawObj.(*profilebindingapi.ProfileBinding)
			if !ok {
				return []string{}
			}

			return pb.Status.ActiveWorkloads
		},
	); err != nil {
		return fmt.Errorf("creating profile binding index: %w", err)
	}

	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &profilebindingapi.ProfileBinding{}, profileRefKey, profileRefIndex,
	); err != nil {
		return fmt.Errorf("creating profile reference index: %w", err)
	}

	status := &bindingStatusReconciler{
		client: r.client,
		reader: r.reader,
		log:    r.log.WithName("status"),
	}

	// Creating or deleting a profile changes the Ready condition of the
	// bindings which refer to it.
	profileEvents := builder.WithPredicates(predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return true },
		DeleteFunc:  func(event.DeleteEvent) bool { return true },
		UpdateFunc:  func(event.UpdateEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
	})

	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name+"-status").
		For(&profilebindingapi.ProfileBinding{}, builder.WithPredicates(
			predicate.GenerationChangedPredicate{},
		)).
		Watches(&seccompprofileapi.SeccompProfile{}, handler.EnqueueRequestsFromMapFunc(
			status.bindingRequests(profilebindingapi.ProfileBindingKindSeccompProfile),
		), profileEvents).
		Watches(&selinuxprofileapi.SelinuxProfile{}, handler.EnqueueRequestsFromMapFunc(
			status.bindingRequests(profilebindingapi.ProfileBindingKindSelinuxProfile),
		), profileEvents).
		Watches(&apparmorprofileapi.AppArmorProfile{}, handler.EnqueueRequestsFromMapFunc(
			status.bindingRequests(profilebindingapi.ProfileBindingKindAppArmorProfile),
		), profileEvents).
		Complete(status); err != nil {
		return fmt.Errorf("creating binding status controller: %w", err)
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
		// Reconcile the tracked pods once a binding enters the cache, for
		// example after an operator restart. Pods deleted while no delete event
		// could be observed are then released from the binding.
		Watches(
			&profilebindingapi.ProfileBinding{},
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

// activeWorkloadRequests maps a binding to reconcile requests for the pods it
// tracks.
func activeWorkloadRequests(_ context.Context, obj client.Object) []reconcile.Request {
	binding, ok := obj.(*profilebindingapi.ProfileBinding)
	if !ok {
		return nil
	}

	requests := make([]reconcile.Request, 0, len(binding.Status.ActiveWorkloads))
	for _, podID := range binding.Status.ActiveWorkloads {
		namespace, name, found := strings.Cut(podID, "/")
		if !found {
			continue
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
		})
	}

	return requests
}
