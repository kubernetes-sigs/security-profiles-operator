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
	"errors"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// podIndex returns an index function over pods for the provided extractor.
// Completed pods are not indexed, because they do not use their profiles
// anymore.
func podIndex(extract func(*corev1.Pod) []string) client.IndexerFunc {
	return func(rawObj client.Object) []string {
		pod, ok := rawObj.(*corev1.Pod)
		if !ok || util.PodCompleted(pod) {
			return []string{}
		}

		return extract(pod)
	}
}

// Setup adds a controller that links the pods to the profiles they use.
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

	// Index the profiles by the pods they list.
	for _, obj := range []client.Object{
		&seccompprofileapi.SeccompProfile{},
		&selinuxprofileapi.SelinuxProfile{},
		&selinuxprofileapi.RawSelinuxProfile{},
		&apparmorprofileapi.AppArmorProfile{},
	} {
		if err := indexer.IndexField(ctx, obj, linkedPodsKey, workloadIndex); err != nil {
			return fmt.Errorf("creating active workloads index: %w", err)
		}
	}

	profileOptions := ctrlcontroller.Options{
		MaxConcurrentReconciles: controller.MaxConcurrentReconciles(ctx),
	}

	if err := errors.Join(
		setupProfileReconciler(mgr, name+"-seccomp", &profileOptions, r, seccompKind),
		setupProfileReconciler(mgr, name+"-selinux", &profileOptions, r, selinuxKind),
		setupProfileReconciler(mgr, name+"-rawselinux", &profileOptions, r, rawSelinuxKind),
		setupProfileReconciler(mgr, name+"-apparmor", &profileOptions, r, appArmorKind),
	); err != nil {
		return err
	}

	profileWatch := handler.EnqueueRequestsFromMapFunc(r.profileWorkloadRequests)

	// Register a special reconciler for pod events
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(controller.Options(ctx)).
		Watches(
			&corev1.Pod{},
			&podEventHandler{EventHandler: &handler.EnqueueRequestForObject{}, pods: r},
			builder.WithPredicates(podPredicate()),
		).
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

// podEventHandler enqueues the pod events like handler.EnqueueRequestForObject
// and remembers the profile references of the deleted pods, which are gone
// from the cache once their deletion gets reconciled. They tell which of the
// profiles that list only part of their pods may count the deleted pod.
type podEventHandler struct {
	handler.EventHandler

	pods *PodReconciler
}

func (h *podEventHandler) Delete(
	ctx context.Context,
	e event.DeleteEvent,
	q workqueue.TypedRateLimitingInterface[reconcile.Request],
) {
	if pod, ok := e.Object.(*corev1.Pod); ok {
		h.pods.rememberDeletedPod(pod)
	}

	h.EventHandler.Delete(ctx, e, q)
}

// setupProfileReconciler adds the profileReconciler of a profile kind.
func setupProfileReconciler[T client.Object](
	mgr ctrl.Manager,
	name string,
	options *ctrlcontroller.Options,
	pods *PodReconciler,
	kind *profileKind[T],
) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(*options).
		For(kind.newObj(), builder.WithPredicates(profileWorkloadsPredicate)).
		Complete(&profileReconciler[T]{pods: pods, kind: kind}); err != nil {
		return fmt.Errorf("creating %s reconciler: %w", kind.name, err)
	}

	return nil
}

// profileWorkloadsPredicate selects the profiles entering the cache and the
// updates of the pods they list or of their in-use finalizer.
var profileWorkloadsPredicate = predicate.Funcs{
	CreateFunc: func(event.CreateEvent) bool { return true },
	DeleteFunc: func(event.DeleteEvent) bool { return false },
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldWorkloads, oldCount := workloadStatus(e.ObjectOld)
		newWorkloads, newCount := workloadStatus(e.ObjectNew)

		return oldCount != newCount || !slices.Equal(oldWorkloads, newWorkloads) ||
			isInUse(e.ObjectOld) != isInUse(e.ObjectNew)
	},
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// podPredicate selects the pod events which can change the profiles in use:
// a pod referencing a profile appears or disappears, or the profiles a pod
// references change. Status updates of a pod, like readiness flaps or
// restarts, keep the profiles as they are and would only cause reconciles
// which look up every profile and change nothing.
func podPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return hasProfile(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return hasProfile(e.Object) },
		UpdateFunc:  podProfilesChanged,
		GenericFunc: func(e event.GenericEvent) bool { return hasProfile(e.Object) },
	}
}

// podProfilesChanged returns true if the new pod references a profile and
// the referenced profiles differ from the old pod, the pod got replaced by
// one with the same name, which the reconciler tells apart by UID, or the pod
// completed.
func podProfilesChanged(e event.UpdateEvent) bool {
	o, ok := e.ObjectOld.(*corev1.Pod)
	if !ok {
		return false
	}

	n, ok := e.ObjectNew.(*corev1.Pod)
	if !ok {
		return false
	}

	return hasProfile(n) && (o.UID != n.UID || util.PodCompletedNow(o, n) ||
		!slices.Equal(getSeccompProfilesFromPod(o), getSeccompProfilesFromPod(n)) ||
		!slices.Equal(getSelinuxProfilesFromPod(o), getSelinuxProfilesFromPod(n)) ||
		!slices.Equal(getAppArmorProfilesFromPod(o), getAppArmorProfilesFromPod(n)))
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
	podIDs, _ := workloadStatus(obj)

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
