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
	"slices"
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

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// podIndex returns an index function over pods for the provided extractor.
func podIndex(extract func(*corev1.Pod) []string) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		pod, ok := rawObj.(*corev1.Pod)
		if !ok {
			return []string{}
		}

		return extract(pod)
	}
}

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
	r.record = util.NewEventRecorder(mgr, name)

	indexer := mgr.GetFieldIndexer()

	for key, extract := range map[string]func(*corev1.Pod) []string{
		spOwnerKey: getSeccompProfilesFromPod,
		seOwnerKey: getSelinuxProfilesFromPod,
		aaOwnerKey: getAppArmorProfilesFromPod,
	} {
		if err := indexer.IndexField(ctx, &corev1.Pod{}, key, podIndex(extract)); err != nil {
			return fmt.Errorf("creating pod index %s: %w", key, err)
		}
	}

	// Index SeccompProfiles with active pods
	if err := indexer.IndexField(
		ctx,
		&seccompprofileapi.SeccompProfile{},
		linkedPodsKey,
		func(rawObj client.Object) []string {
			sp, ok := rawObj.(*seccompprofileapi.SeccompProfile)
			if !ok {
				return []string{}
			}

			return sp.Status.ActiveWorkloads
		},
	); err != nil {
		return fmt.Errorf("creating seccomp profile index: %w", err)
	}

	// Index the AppArmor and raw SELinux profiles in use, which have no list
	// of active workloads to index.
	for _, obj := range []client.Object{
		&apparmorprofileapi.AppArmorProfile{}, &selinuxprofileapi.RawSelinuxProfile{},
	} {
		if err := indexer.IndexField(ctx, obj, inUseKey, inUseIndex); err != nil {
			return fmt.Errorf("creating in-use profile index: %w", err)
		}
	}

	// Index SelinuxProfile with active pods
	if err := indexer.IndexField(
		ctx,
		&selinuxprofileapi.SelinuxProfile{},
		linkedPodsKey,
		func(rawObj client.Object) []string {
			sp, ok := rawObj.(*selinuxprofileapi.SelinuxProfile)
			if !ok {
				return []string{}
			}

			return sp.Status.ActiveWorkloads
		},
	); err != nil {
		return fmt.Errorf("creating selinux profile index: %w", err)
	}

	profileWatch := handler.EnqueueRequestsFromMapFunc(r.profileWorkloadRequests)

	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name+"-apparmor").
		For(&apparmorprofileapi.AppArmorProfile{}, builder.WithPredicates(profileCreatedPredicate)).
		Complete(&profileReleaser[*apparmorprofileapi.AppArmorProfile]{
			pods:   r,
			newObj: func() *apparmorprofileapi.AppArmorProfile { return &apparmorprofileapi.AppArmorProfile{} },
			release: func(ctx context.Context, r *PodReconciler, p *apparmorprofileapi.AppArmorProfile) error {
				return r.updatePodReferencesForAppArmor(ctx, p)
			},
		}); err != nil {
		return fmt.Errorf("creating AppArmorProfile releaser: %w", err)
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name+"-rawselinux").
		For(&selinuxprofileapi.RawSelinuxProfile{}, builder.WithPredicates(profileCreatedPredicate)).
		Complete(&profileReleaser[*selinuxprofileapi.RawSelinuxProfile]{
			pods:   r,
			newObj: func() *selinuxprofileapi.RawSelinuxProfile { return &selinuxprofileapi.RawSelinuxProfile{} },
			release: func(ctx context.Context, r *PodReconciler, p *selinuxprofileapi.RawSelinuxProfile) error {
				return r.updatePodReferencesForRawSelinux(ctx, p)
			},
		}); err != nil {
		return fmt.Errorf("creating RawSelinuxProfile releaser: %w", err)
	}

	// Register a special reconciler for pod events
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return hasProfile(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return hasProfile(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return hasProfile(e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return hasProfile(e.Object) },
		})).
		// Reconcile the pods using a profile once the profile enters the
		// cache, for example after an operator restart or if the profile got
		// created after the pod. Pods deleted while no delete event could be
		// observed are then released from the profile.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			profileWatch,
			builder.WithPredicates(profileCreatedPredicate),
		).
		Watches(
			&selinuxprofileapi.SelinuxProfile{},
			profileWatch,
			builder.WithPredicates(profileCreatedPredicate),
		).
		Watches(
			&selinuxprofileapi.RawSelinuxProfile{},
			profileWatch,
			builder.WithPredicates(profileCreatedPredicate),
		).
		Watches(
			&apparmorprofileapi.AppArmorProfile{},
			profileWatch,
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

// profileWorkloadRequests maps a profile to reconcile requests for the pods
// which use it, either according to its status or to the pod index.
func (r *PodReconciler) profileWorkloadRequests(
	ctx context.Context,
	obj client.Object,
) []reconcile.Request {
	requests := activeWorkloadRequests(ctx, obj)

	var ownerKey, reference string

	switch profile := obj.(type) {
	case *seccompprofileapi.SeccompProfile:
		ownerKey, reference = spOwnerKey, seccompProfileReference(profile)
	case *selinuxprofileapi.SelinuxProfile:
		ownerKey, reference = seOwnerKey, profile.GetPolicyUsage()
	case *selinuxprofileapi.RawSelinuxProfile:
		ownerKey, reference = seOwnerKey, profile.GetPolicyUsage()
	case *apparmorprofileapi.AppArmorProfile:
		ownerKey, reference = aaOwnerKey, profile.GetProfileName()
	default:
		return requests
	}

	pods := &corev1.PodList{}
	if err := r.client.List(ctx, pods, client.MatchingFields{ownerKey: reference}); err != nil {
		r.log.Error(err, "cannot list pods using profile", "profile", obj.GetName())

		return requests
	}

	for i := range pods.Items {
		request := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pods.Items[i])}
		if !slices.Contains(requests, request) {
			requests = append(requests, request)
		}
	}

	return requests
}

// activeWorkloadRequests maps a profile to reconcile requests for the pods
// in its list of active workloads.
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

// hasProfile returns true if the pod references a profile which can be
// managed by the operator.
func hasProfile(obj runtime.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return len(getSeccompProfilesFromPod(pod)) > 0 ||
		len(getSelinuxProfilesFromPod(pod)) > 0 ||
		len(getAppArmorProfilesFromPod(pod)) > 0
}
