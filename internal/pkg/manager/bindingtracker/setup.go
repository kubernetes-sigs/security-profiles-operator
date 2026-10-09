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
	"slices"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
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

	operatorNamespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		operatorNamespace = config.OperatorName
	}

	// The SPOD controller enables SELinux by default on OpenShift, which it
	// detects like this once on startup.
	caInjectType, err := bindata.GetCAInjectType(ctx, r.log, r.reader)
	if err != nil {
		return fmt.Errorf("detecting the platform: %w", err)
	}

	status := &bindingStatusReconciler{
		client:            r.client,
		reader:            r.reader,
		log:               r.log.WithName("status"),
		operatorNamespace: operatorNamespace,
		isOpenShift:       caInjectType == bindata.CAInjectTypeOpenShift,
	}

	// Creating or deleting a profile and changing its state change the Ready
	// condition of the bindings which refer to it.
	profileEvents := builder.WithPredicates(predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		DeleteFunc: func(event.DeleteEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return profileState(e.ObjectOld) != profileState(e.ObjectNew)
		},
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
		WithOptions(controller.Options(ctx)).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: func(_ event.CreateEvent) bool { return true },
			DeleteFunc: func(_ event.DeleteEvent) bool { return true },
			UpdateFunc: func(e event.UpdateEvent) bool {
				return trackedPodChanged(e.ObjectOld, e.ObjectNew)
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

// trackedPodChanged reports whether an update of a pod may change the bindings
// it uses. The webhook applies the bindings of ephemeral containers through
// their subresource, which cannot change the annotation of the applied
// bindings, so their images are compared as well. A completed pod does not use
// its bindings anymore.
func trackedPodChanged(oldObj, newObj client.Object) bool {
	if !reflect.DeepEqual(oldObj.GetLabels(), newObj.GetLabels()) ||
		oldObj.GetAnnotations()[profilebindingapi.AppliedBindingsAnnotation] !=
			newObj.GetAnnotations()[profilebindingapi.AppliedBindingsAnnotation] ||
		util.PodCompletedNow(oldObj, newObj) {
		return true
	}

	oldPod, oldOk := oldObj.(*corev1.Pod)
	newPod, newOk := newObj.(*corev1.Pod)

	if !oldOk || !newOk {
		return false
	}

	return !slices.EqualFunc(
		oldPod.Spec.EphemeralContainers, newPod.Spec.EphemeralContainers,
		func(a, b corev1.EphemeralContainer) bool {
			return a.Name == b.Name && a.Image == b.Image
		},
	)
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
