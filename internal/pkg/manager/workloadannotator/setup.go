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

package workloadannotator

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *PodReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "pods"

	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.Name())
	//nolint:staticcheck // TODO: migrate to GetEventRecorder
	r.record = mgr.GetEventRecorderFor(name)

	// Index Pods using seccomp profiles
	if err := mgr.GetFieldIndexer().
		IndexField(ctx, &corev1.Pod{}, spOwnerKey, func(rawObj client.Object) []string {
			pod, ok := rawObj.(*corev1.Pod)
			if !ok {
				return []string{}
			}

			return getSeccompProfilesFromPod(pod)
		}); err != nil {
		return fmt.Errorf("creating pod index: %w", err)
	}

	// Index Pods using selinux profiles
	if err := mgr.GetFieldIndexer().
		IndexField(ctx, &corev1.Pod{}, seOwnerKey, func(rawObj client.Object) []string {
			pod, ok := rawObj.(*corev1.Pod)
			if !ok {
				return []string{}
			}

			return getSelinuxProfilesFromPod(ctx, r, pod)
		}); err != nil {
		return fmt.Errorf("creating pod index: %w", err)
	}

	// Index SeccompProfiles with active pods
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &seccompprofileapi.SeccompProfile{}, linkedPodsKey, func(rawObj client.Object) []string {
			sp, ok := rawObj.(*seccompprofileapi.SeccompProfile)
			if !ok {
				return []string{}
			}

			return sp.Status.ActiveWorkloads
		}); err != nil {
		return fmt.Errorf("creating seccomp profile index: %w", err)
	}

	// Index SelinuxProfile with active pods
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &selinuxprofileapi.SelinuxProfile{}, linkedPodsKey, func(rawObj client.Object) []string {
			sp, ok := rawObj.(*selinuxprofileapi.SelinuxProfile)
			if !ok {
				return []string{}
			}

			return sp.Status.ActiveWorkloads
		}); err != nil {
		return fmt.Errorf("creating selinux profile index: %w", err)
	}

	// Register a special reconciler for pod events
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return r.hasValidProfile(ctx, e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return r.hasValidProfile(ctx, e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return r.hasValidProfile(ctx, e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return r.hasValidProfile(ctx, e.Object) },
		})).
		// Reconcile the pods using a profile once the profile enters the
		// cache, for example after an operator restart. Pods deleted while no
		// delete event could be observed are then released from the profile.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(activeWorkloadRequests),
			builder.WithPredicates(profileCreatedPredicate),
		).
		Watches(
			&selinuxprofileapi.SelinuxProfile{},
			handler.EnqueueRequestsFromMapFunc(activeWorkloadRequests),
			builder.WithPredicates(profileCreatedPredicate),
		).
		Complete(r)
}

// profileCreatedPredicate selects only the create events of profiles.
var profileCreatedPredicate = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return true },
	DeleteFunc:  func(event.DeleteEvent) bool { return false },
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// activeWorkloadRequests maps a profile to reconcile requests for the pods
// using it.
func activeWorkloadRequests(_ context.Context, obj client.Object) []reconcile.Request {
	var podIDs []string

	switch profile := obj.(type) {
	case *seccompprofileapi.SeccompProfile:
		podIDs = profile.Status.ActiveWorkloads
	case *selinuxprofileapi.SelinuxProfile:
		podIDs = profile.Status.ActiveWorkloads
	default:
		return nil
	}

	requests := make([]reconcile.Request, 0, len(podIDs))
	for _, podID := range podIDs {
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

func hasSeccompProfile(obj runtime.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return len(getSeccompProfilesFromPod(pod)) > 0
}

func hasSelinuxProfile(ctx context.Context, r *PodReconciler, obj runtime.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return len(getSelinuxProfilesFromPod(ctx, r, pod)) > 0
}

func (r *PodReconciler) hasValidProfile(ctx context.Context, obj runtime.Object) bool {
	return hasSeccompProfile(obj) || hasSelinuxProfile(ctx, r, obj)
}
