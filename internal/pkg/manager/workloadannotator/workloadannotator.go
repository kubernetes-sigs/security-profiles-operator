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
	"iter"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	spOwnerKey    = ".metadata.seccompProfileOwner"
	seOwnerKey    = ".metadata.selinuxProfileOwner"
	aaOwnerKey    = ".metadata.apparmorProfileOwner"
	linkedPodsKey = ".metadata.activeWorkloads"
	// truncatedValue is indexed under linkedPodsKey for the profiles which
	// list only part of the pods using them. Pod identifiers contain a slash,
	// so they cannot clash with it.
	truncatedValue = "truncated"
	// maxActiveWorkloads limits the pods listed in the status of a profile,
	// so that a profile used by very many pods stays far below the size limit
	// of etcd. Whether a profile is in use follows the pod index, not the
	// list.
	maxActiveWorkloads = 1000
	reconcileTimeout   = 1 * time.Minute
	pathParts          = 2

	seccompOperatorDir = "operator/"
	selinuxTypeSuffix  = ".process"
	localhostPrefix    = "localhost/"
	reasonReconcileErr = "ReconcileError"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &PodReconciler{}
}

// A PodReconciler monitors pod changes and links them to the profiles they
// use.
type PodReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
	record util.EventRecorder

	// deletedMu guards deleted, which holds the profile references of the
	// deleted pods whose deletion is not reconciled yet, see
	// podEventHandler.
	deletedMu sync.Mutex
	deleted   map[string]podReferences
}

// podReferences are the profile references of a pod, as the profiles of each
// kind return them.
type podReferences struct {
	seccomp, selinux, appArmor []string
}

func referencesOf(pod *corev1.Pod) podReferences {
	return podReferences{
		seccomp:  getSeccompProfilesFromPod(pod),
		selinux:  getSelinuxProfilesFromPod(pod),
		appArmor: getAppArmorProfilesFromPod(pod),
	}
}

// rememberDeletedPod keeps the profile references of a deleted pod until its
// deletion got reconciled. The pod is gone from the cache by then.
func (r *PodReconciler) rememberDeletedPod(pod *corev1.Pod) {
	r.deletedMu.Lock()
	defer r.deletedMu.Unlock()

	if r.deleted == nil {
		r.deleted = map[string]podReferences{}
	}

	r.deleted[pod.Namespace+"/"+pod.Name] = referencesOf(pod)
}

// deletedPod returns the profile references of the deleted pod, if known.
func (r *PodReconciler) deletedPod(podID string) (podReferences, bool) {
	r.deletedMu.Lock()
	defer r.deletedMu.Unlock()

	refs, ok := r.deleted[podID]

	return refs, ok
}

// forgetDeletedPod drops the profile references of the deleted pod once its
// deletion got reconciled.
func (r *PodReconciler) forgetDeletedPod(podID string) {
	r.deletedMu.Lock()
	defer r.deletedMu.Unlock()

	delete(r.deleted, podID)
}

// Name returns the name of the controller.
func (r *PodReconciler) Name() string {
	return "workload-annotator"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *PodReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return nil
}

// Healthz is the liveness probe endpoint of the controller.
func (r *PodReconciler) Healthz(*http.Request) error {
	return nil
}

// Namespace scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile reacts to pod events and marks the profiles used by a pod as in
// use, or releases them once no pod uses them anymore.
func (r *PodReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	pod := &corev1.Pod{}

	podID := req.Namespace + "/" + req.Name

	deletedRefs, deletedKnown := r.deletedPod(podID)

	err := r.client.Get(ctx, req.NamespacedName, pod)
	if kerrors.IsNotFound(err) {
		var refs *podReferences
		if deletedKnown {
			refs = &deletedRefs
		}

		return reconcile.Result{}, r.handlePodDeletion(ctx, podID, refs)
	}

	if err != nil {
		// The controller logs the returned error.
		return reconcile.Result{}, fmt.Errorf("looking up pod in pod reconciler: %w", err)
	}

	// A completed pod, like the one of a finished Job, does not use its
	// profiles anymore, although it exists until it gets deleted.
	if util.PodCompleted(pod) {
		refs := referencesOf(pod)

		return reconcile.Result{}, r.handlePodDeletion(ctx, podID, &refs)
	}

	// A pod can be replaced by one with the same name, like the pods of a
	// StatefulSet, before the deletion of the old one got reconciled. The
	// profiles which only the old pod used have to be released then,
	// including the ones which list only part of their pods, if the deletion
	// of the old pod told which profiles it used.
	refs := referencesOf(pod)
	oldRefs := deletedRefs

	truncated := func([]string) func(string) bool { return nil }
	if deletedKnown {
		truncated = usedBy
	}

	errs := []error{
		r.handlePodUpdate(ctx, logger, pod),
		seccompKind.release(ctx, r, podID, truncated(oldRefs.seccomp), usedBy(refs.seccomp)),
		selinuxKind.release(ctx, r, podID, truncated(oldRefs.selinux), usedBy(refs.selinux)),
		rawSelinuxKind.release(ctx, r, podID, truncated(oldRefs.selinux), usedBy(refs.selinux)),
		appArmorKind.release(ctx, r, podID, truncated(oldRefs.appArmor), usedBy(refs.appArmor)),
	}

	updateErr := errors.Join(errs...)
	if updateErr == nil && deletedKnown {
		r.forgetDeletedPod(podID)
	}

	if updateErr != nil {
		r.record.Eventf(
			pod, nil, corev1.EventTypeWarning, reasonReconcileErr, util.EventActionReconcile,
			"%s", updateErr.Error(),
		)

		return reconcile.Result{}, updateErr
	}

	return reconcile.Result{}, nil
}

// usedBy returns a function which tells if a profile reference is one of the
// provided references of a pod.
func usedBy(references []string) func(string) bool {
	return func(reference string) bool { return slices.Contains(references, reference) }
}

// handlePodDeletion updates all profiles which were used by the deleted or
// completed pod. refs are the profile references of the pod, nil if unknown.
func (r *PodReconciler) handlePodDeletion(
	ctx context.Context, podID string, refs *podReferences,
) error {
	// The profiles which list only part of their pods may count the pod
	// without listing it, so the ones the pod used are updated as well. If
	// the pod is unknown, for example because it got deleted before its
	// creation got reconciled, all of them have to be checked.
	truncated := func(references func(*podReferences) []string) func(string) bool {
		if refs == nil {
			return func(string) bool { return true }
		}

		return usedBy(references(refs))
	}

	// Every profile kind is released on its own, so that a failure with one
	// kind does not keep the profiles of the other kinds in use.
	errs := []error{
		seccompKind.release(ctx, r, podID,
			truncated(func(p *podReferences) []string { return p.seccomp }), nil),
		selinuxKind.release(ctx, r, podID,
			truncated(func(p *podReferences) []string { return p.selinux }), nil),
		rawSelinuxKind.release(ctx, r, podID,
			truncated(func(p *podReferences) []string { return p.selinux }), nil),
		appArmorKind.release(ctx, r, podID,
			truncated(func(p *podReferences) []string { return p.appArmor }), nil),
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("updating profiles for deleted pod: %w", err)
	}

	r.forgetDeletedPod(podID)

	return nil
}

func isInUse(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, util.HasActivePodsFinalizerString)
}

// handlePodUpdate marks every profile used by the pod as in use. A profile
// which cannot be found does not stop the other profiles from being marked:
// it is reported and picked up again once it gets created.
func (r *PodReconciler) handlePodUpdate(
	ctx context.Context, logger logr.Logger, pod *corev1.Pod,
) error {
	var errs []error

	missing := func(kind, name string) {
		logger.Info("Profile used by pod not found", "kind", kind, "profile", name)
		r.record.Eventf(
			pod, nil, corev1.EventTypeWarning, reasonReconcileErr, util.EventActionReconcile,
			"%s %s used by the pod not found", kind, name,
		)
	}

	for _, profilePath := range getSeccompProfilesFromPod(pod) {
		profiles, err := r.seccompProfilesForPath(ctx, profilePath)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		if len(profiles) == 0 {
			missing("SeccompProfile", profilePath)

			continue
		}

		for _, sp := range profiles {
			errs = append(errs, r.updatePodReferencesForSeccomp(ctx, sp))
		}
	}

	for _, usage := range getSelinuxProfilesFromPod(pod) {
		name := strings.TrimSuffix(usage, selinuxTypeSuffix)

		found, err := r.updateSelinuxProfilesByName(ctx, name)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		// Other tools like udica create "<name>.process" types as well, so a
		// missing profile is not reported as an error.
		if !found {
			logger.V(config.VerboseLevel).Info(
				"SELinux type used by pod does not belong to a profile", "type", usage,
			)
		}
	}

	for _, name := range getAppArmorProfilesFromPod(pod) {
		profile := &apparmorprofileapi.AppArmorProfile{}
		if err := r.client.Get(ctx, util.NamespacedName(name, ""), profile); err != nil {
			// A localhost AppArmor profile does not have to be managed by
			// the operator, so a missing one is not reported.
			if !kerrors.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("looking up AppArmorProfile %s: %w", name, err))
			}

			continue
		}

		errs = append(errs, r.updatePodReferencesForAppArmor(ctx, profile))
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("updating profiles for new or updated pod: %w", err)
	}

	return nil
}

// seccompProfilesForPath returns the profiles which are stored at the
// provided localhost profile path. The file name of a profile gets a ".json"
// suffix unless its name already has it, so "operator/foo.json" can belong to
// a profile named "foo" as well as to one named "foo.json".
func (r *PodReconciler) seccompProfilesForPath(
	ctx context.Context, profilePath string,
) ([]*seccompprofileapi.SeccompProfile, error) {
	file := strings.TrimPrefix(profilePath, seccompOperatorDir)
	candidates := []string{strings.TrimSuffix(file, seccompprofileapi.ExtJSON), file}

	var profiles []*seccompprofileapi.SeccompProfile

	for _, name := range slices.Compact(candidates) {
		sp := &seccompprofileapi.SeccompProfile{}
		if err := r.client.Get(ctx, util.NamespacedName(name, ""), sp); err != nil {
			if kerrors.IsNotFound(err) {
				continue
			}

			return nil, fmt.Errorf("looking up SeccompProfile %s: %w", name, err)
		}

		if sp.GetProfileFile() == file {
			profiles = append(profiles, sp)
		}
	}

	return profiles, nil
}

// updateSelinuxProfilesByName marks the SelinuxProfile and the
// RawSelinuxProfile with the provided name as in use. Both kinds result in the
// same SELinux type. It returns false if neither exists.
func (r *PodReconciler) updateSelinuxProfilesByName(
	ctx context.Context,
	name string,
) (bool, error) {
	found := false

	selinuxProfile := &selinuxprofileapi.SelinuxProfile{}

	err := r.client.Get(ctx, util.NamespacedName(name, ""), selinuxProfile)
	if err == nil {
		found = true

		if err := r.updatePodReferencesForSelinux(ctx, selinuxProfile); err != nil {
			return found, err
		}
	} else if !kerrors.IsNotFound(err) {
		return found, fmt.Errorf("looking up SelinuxProfile %s: %w", name, err)
	}

	rawProfile := &selinuxprofileapi.RawSelinuxProfile{}

	err = r.client.Get(ctx, util.NamespacedName(name, ""), rawProfile)
	if err == nil {
		found = true

		return found, r.updatePodReferencesForRawSelinux(ctx, rawProfile)
	} else if !kerrors.IsNotFound(err) {
		return found, fmt.Errorf("looking up RawSelinuxProfile %s: %w", name, err)
	}

	return found, nil
}

// profileKind describes how the pods reference the profiles of a kind and
// where the profiles list the pods using them.
type profileKind[T client.Object] struct {
	// name is the kind of the profiles.
	name string
	// ownerKey is the pod index of the profile references.
	ownerKey string
	// reference returns how the pods reference the profile.
	reference func(T) string
	// status returns the active workloads and their count in the status of
	// the profile.
	status  func(T) (*[]string, *int32)
	newObj  func() T
	newList func() client.ObjectList
}

var (
	seccompKind = &profileKind[*seccompprofileapi.SeccompProfile]{
		name:      "SeccompProfile",
		ownerKey:  spOwnerKey,
		reference: seccompProfileReference,
		status: func(p *seccompprofileapi.SeccompProfile) (*[]string, *int32) {
			return &p.Status.ActiveWorkloads, &p.Status.ActiveWorkloadsCount
		},
		newObj:  func() *seccompprofileapi.SeccompProfile { return &seccompprofileapi.SeccompProfile{} },
		newList: func() client.ObjectList { return &seccompprofileapi.SeccompProfileList{} },
	}
	selinuxKind = &profileKind[*selinuxprofileapi.SelinuxProfile]{
		name:      "SelinuxProfile",
		ownerKey:  seOwnerKey,
		reference: (*selinuxprofileapi.SelinuxProfile).GetPolicyUsage,
		status: func(p *selinuxprofileapi.SelinuxProfile) (*[]string, *int32) {
			return &p.Status.ActiveWorkloads, &p.Status.ActiveWorkloadsCount
		},
		newObj:  func() *selinuxprofileapi.SelinuxProfile { return &selinuxprofileapi.SelinuxProfile{} },
		newList: func() client.ObjectList { return &selinuxprofileapi.SelinuxProfileList{} },
	}
	rawSelinuxKind = &profileKind[*selinuxprofileapi.RawSelinuxProfile]{
		name:      "RawSelinuxProfile",
		ownerKey:  seOwnerKey,
		reference: (*selinuxprofileapi.RawSelinuxProfile).GetPolicyUsage,
		status: func(p *selinuxprofileapi.RawSelinuxProfile) (*[]string, *int32) {
			return &p.Status.ActiveWorkloads, &p.Status.ActiveWorkloadsCount
		},
		newObj:  func() *selinuxprofileapi.RawSelinuxProfile { return &selinuxprofileapi.RawSelinuxProfile{} },
		newList: func() client.ObjectList { return &selinuxprofileapi.RawSelinuxProfileList{} },
	}
	appArmorKind = &profileKind[*apparmorprofileapi.AppArmorProfile]{
		name:      "AppArmorProfile",
		ownerKey:  aaOwnerKey,
		reference: (*apparmorprofileapi.AppArmorProfile).GetProfileName,
		status: func(p *apparmorprofileapi.AppArmorProfile) (*[]string, *int32) {
			return &p.Status.ActiveWorkloads, &p.Status.ActiveWorkloadsCount
		},
		newObj:  func() *apparmorprofileapi.AppArmorProfile { return &apparmorprofileapi.AppArmorProfile{} },
		newList: func() client.ObjectList { return &apparmorprofileapi.AppArmorProfileList{} },
	}
)

// workloadStatus returns the active workloads and their count in the status
// of a profile of any kind.
func workloadStatus(obj client.Object) (workloads []string, count int32) {
	switch p := obj.(type) {
	case *seccompprofileapi.SeccompProfile:
		return p.Status.ActiveWorkloads, p.Status.ActiveWorkloadsCount
	case *selinuxprofileapi.SelinuxProfile:
		return p.Status.ActiveWorkloads, p.Status.ActiveWorkloadsCount
	case *selinuxprofileapi.RawSelinuxProfile:
		return p.Status.ActiveWorkloads, p.Status.ActiveWorkloadsCount
	case *apparmorprofileapi.AppArmorProfile:
		return p.Status.ActiveWorkloads, p.Status.ActiveWorkloadsCount
	default:
		return nil, 0
	}
}

// workloadIndex indexes the profiles by the pods they list, and the ones
// which list only part of their pods by truncatedValue.
func workloadIndex(obj client.Object) []string {
	workloads, count := workloadStatus(obj)
	if int(count) > len(workloads) {
		return append(slices.Clone(workloads), truncatedValue)
	}

	return workloads
}

// release updates the profiles of the kind which list the pod as active
// workload, except the ones whose reference used reports as still used by
// the pod. It updates the profiles which list only part of their pods as
// well, if truncated reports their reference as used by the pod before.
func (k *profileKind[T]) release(
	ctx context.Context,
	r *PodReconciler,
	podID string,
	truncated func(string) bool,
	used func(string) bool,
) error {
	values := []string{podID}
	if truncated != nil {
		values = append(values, truncatedValue)
	}

	seen := sets.New[string]()

	var errs []error

	for _, value := range values {
		profiles := k.newList()
		if err := r.client.List(
			ctx, profiles, client.MatchingFields{linkedPodsKey: value},
		); err != nil {
			errs = append(errs, fmt.Errorf("listing %ss of pod: %w", k.name, err))

			continue
		}

		if err := meta.EachListItem(profiles, func(obj runtime.Object) error {
			profile, ok := obj.(T)
			if !ok || seen.Has(profile.GetName()) ||
				(used != nil && used(k.reference(profile))) ||
				(value == truncatedValue && !truncated(k.reference(profile))) {
				return nil
			}

			seen.Insert(profile.GetName())
			errs = append(errs, k.update(ctx, r, profile))

			return nil
		}); err != nil {
			errs = append(errs, fmt.Errorf("iterating %ss of pod: %w", k.name, err))
		}
	}

	return errors.Join(errs...)
}

// update updates a profile with the identifiers of the pods using it and
// ensures it carries a finalizer indicating it is in use, so that it cannot
// be deleted from under a running workload.
//
// The status gets patched as the cache has the profile, so that a pod event
// costs no read from the API server. The patch carries the resource version
// of the profile and fails with a conflict if the cache is behind or another
// reconcile wrote the profile in the meantime. Every retry then reads the
// profile from the API server and lists the pods again, instead of dropping
// the pods the other reconcile added. A profile which the cache shows with
// the current pods already is not written. If the cache was behind in that
// case, the profile gets reconciled again once the cache catches up, see
// profileReconciler.
func (k *profileKind[T]) update(ctx context.Context, r *PodReconciler, prof T) error {
	reference := k.reference(prof)

	linkedPods := func() ([]string, error) {
		pods := &corev1.PodList{}

		// The pods are only read, so the cache does not have to copy them.
		err := r.client.List(
			ctx, pods,
			client.MatchingFields{k.ownerKey: reference},
			client.UnsafeDisableDeepCopy,
		)
		if client.IgnoreNotFound(err) != nil {
			return nil, fmt.Errorf("listing pods to update %s: %w", k.name, err)
		}

		podList := make([]string, len(pods.Items))

		for i := range pods.Items {
			podList[i] = pods.Items[i].Namespace + "/" + pods.Items[i].Name
		}

		return podList, nil
	}

	pods, err := linkedPods()
	if err != nil {
		return err
	}

	cached := true
	profileDeleted := false

	if err := util.RetryWithContext(ctx, func() error {
		if !cached {
			if err := r.reader.Get(ctx, client.ObjectKeyFromObject(prof), prof); err != nil {
				if kerrors.IsNotFound(err) {
					profileDeleted = true

					return nil
				}

				return fmt.Errorf("retrieving profile: %w", err)
			}

			current, err := linkedPods()
			if err != nil {
				return err
			}

			pods = current
		}

		cached = false

		workloads, count := k.status(prof)
		listed, total := activeWorkloads(pods, *workloads)

		if *count == total && sameActiveWorkloads(*workloads, listed) {
			return nil
		}

		base, ok := prof.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("copying %s %s", k.name, prof.GetName())
		}

		*workloads, *count = listed, total

		if err := r.client.Status().Patch(
			ctx, prof, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}),
		); err != nil {
			return fmt.Errorf("patching profile: %w", err)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating %s status: %w", k.name, err)
	}

	if profileDeleted {
		return nil
	}

	return updateInUseFinalizer(ctx, r, prof, len(pods) > 0, linkedPods)
}

// activeWorkloads returns the sorted pods which the status of a profile lists,
// at most maxActiveWorkloads of them, and the number of all pods. The pods
// only get sorted if the currently listed ones are not the first of them
// anymore, so that a pod which goes away without being listed does not sort
// all pods of a profile which lists only part of them.
func activeWorkloads(pods, current []string) (listed []string, total int32) {
	if len(pods) == 0 {
		return nil, 0
	}

	total = int32(min(len(pods), math.MaxInt32))

	if listsFirstPods(pods, current) {
		return slices.Clone(current), total
	}

	sorted := slices.Sorted(slices.Values(pods))

	return sorted[:min(len(sorted), maxActiveWorkloads)], total
}

// listsFirstPods returns true if the listed pods are the first ones of the
// pods in sort order, as many as the status of a profile lists.
func listsFirstPods(pods, listed []string) bool {
	if len(listed) != min(len(pods), maxActiveWorkloads) || !slices.IsSorted(listed) {
		return false
	}

	last := listed[len(listed)-1]
	found := 0

	for _, pod := range pods {
		if pod > last {
			continue
		}

		if _, ok := slices.BinarySearch(listed, pod); !ok {
			return false
		}

		found++
	}

	return found == len(listed)
}

// updateInUseFinalizer adds the in-use finalizer to the profile if pods use
// it and removes it otherwise. Nothing gets read from the API server or
// written if the provided profile has the finalizer it needs. Otherwise every
// attempt reads the profile and lists the pods again, so that a pod which
// started using the profile in the meantime keeps the finalizer in place.
//
// The API server rejects adding a finalizer to a profile which is being
// deleted, so such a profile does not get it. Its status still lists the pods
// using it.
func updateInUseFinalizer(
	ctx context.Context,
	r *PodReconciler,
	prof client.Object,
	inUse bool,
	linkedPods func() ([]string, error),
) error {
	if inUse == isInUse(prof) || (inUse && !prof.GetDeletionTimestamp().IsZero()) {
		return nil
	}

	if err := util.RetryWithContext(ctx, func() error {
		if err := r.reader.Get(
			ctx, util.NamespacedName(prof.GetName(), prof.GetNamespace()), prof,
		); err != nil {
			return client.IgnoreNotFound(err)
		}

		pods, err := linkedPods()
		if err != nil {
			return err
		}

		inUse := len(pods) > 0
		if inUse == isInUse(prof) || (inUse && !prof.GetDeletionTimestamp().IsZero()) {
			return nil
		}

		if inUse {
			controllerutil.AddFinalizer(prof, util.HasActivePodsFinalizerString)
		} else {
			controllerutil.RemoveFinalizer(prof, util.HasActivePodsFinalizerString)
		}

		return client.IgnoreNotFound(r.client.Update(ctx, prof))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating finalizer: %w", err)
	}

	return nil
}

// seccompProfileReference returns the localhost profile path of the profile,
// as pods reference it.
func seccompProfileReference(sp *seccompprofileapi.SeccompProfile) string {
	return seccompOperatorDir + sp.GetProfileFile()
}

func sameActiveWorkloads(current, desired []string) bool {
	if len(current) != len(desired) {
		return false
	}

	currentCopy := slices.Clone(current)
	desiredCopy := slices.Clone(desired)

	slices.Sort(currentCopy)
	slices.Sort(desiredCopy)

	return slices.Equal(currentCopy, desiredCopy)
}

// updatePodReferencesForSeccomp updates a SeccompProfile with the identifiers
// of pods using it and ensures it has a finalizer indicating it is in use to
// prevent it from being deleted.
func (r *PodReconciler) updatePodReferencesForSeccomp(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
) error {
	return seccompKind.update(ctx, r, sp)
}

// updatePodReferencesForSelinux updates a SelinuxProfile like
// updatePodReferencesForSeccomp.
func (r *PodReconciler) updatePodReferencesForSelinux(
	ctx context.Context,
	se *selinuxprofileapi.SelinuxProfile,
) error {
	return selinuxKind.update(ctx, r, se)
}

// updatePodReferencesForRawSelinux updates a RawSelinuxProfile like
// updatePodReferencesForSeccomp.
func (r *PodReconciler) updatePodReferencesForRawSelinux(
	ctx context.Context,
	se *selinuxprofileapi.RawSelinuxProfile,
) error {
	return rawSelinuxKind.update(ctx, r, se)
}

// updatePodReferencesForAppArmor updates an AppArmorProfile like
// updatePodReferencesForSeccomp.
func (r *PodReconciler) updatePodReferencesForAppArmor(
	ctx context.Context,
	aa *apparmorprofileapi.AppArmorProfile,
) error {
	return appArmorKind.update(ctx, r, aa)
}

// profileReconciler reconciles the profiles of a kind once they enter the
// cache, and whenever the pods they list or their in-use finalizer change.
// Pod events alone miss two cases: a pod which went away while the operator
// did not run produces no event, and the reconcile of a pod deleted right
// after the reconcile which listed it in a profile may look up the profile
// before the cache has that update. The cache gets the update later on,
// which reconciles the profile, and the pod index tells then that the pod is
// gone.
type profileReconciler[T client.Object] struct {
	pods *PodReconciler
	kind *profileKind[T]
}

func (p *profileReconciler[T]) Reconcile(
	ctx context.Context, req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	profile := p.kind.newObj()
	if err := p.pods.client.Get(ctx, req.NamespacedName, profile); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	return reconcile.Result{}, p.kind.update(ctx, p.pods, profile)
}

// allContainers iterates over the regular, init and ephemeral containers of
// the pod without copying them, because the profile extractors run on every
// pod event.
func allContainers(pod *corev1.Pod) iter.Seq[*corev1.Container] {
	return func(yield func(*corev1.Container) bool) {
		for i := range pod.Spec.Containers {
			if !yield(&pod.Spec.Containers[i]) {
				return
			}
		}

		for i := range pod.Spec.InitContainers {
			if !yield(&pod.Spec.InitContainers[i]) {
				return
			}
		}

		for i := range pod.Spec.EphemeralContainers {
			ctr := corev1.Container(pod.Spec.EphemeralContainers[i].EphemeralContainerCommon)
			if !yield(&ctr) {
				return
			}
		}
	}
}

// getSeccompProfilesFromPod returns a slice of strings representing seccomp profiles required by the pod.
// It looks first at the pod spec level, then in each container and init container, then in the annotations.
func getSeccompProfilesFromPod(pod *corev1.Pod) []string {
	profiles := []string{}
	// try to get profile from pod securityContext
	sc := pod.Spec.SecurityContext
	if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
		profiles = append(profiles, *sc.SeccompProfile.LocalhostProfile)
	}

	// try to get profile(s) from securityContext in pods
	for ctr := range allContainers(pod) {
		sc := ctr.SecurityContext
		if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
			profileString := *sc.SeccompProfile.LocalhostProfile
			if !slices.Contains(profiles, profileString) {
				profiles = append(profiles, profileString)
			}
		}
	}

	// try to get profile from annotations
	annotation, hasAnnotation := pod.GetAnnotations()[corev1.SeccompPodAnnotationKey]
	if hasAnnotation && strings.HasPrefix(annotation, localhostPrefix) {
		profileString := strings.TrimPrefix(annotation, localhostPrefix)
		spCheck := &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &profileString,
		}

		if !slices.Contains(profiles, profileString) && isOperatorSeccompProfile(spCheck) {
			profiles = append(profiles, profileString)
		}
	}

	return profiles
}

// getSelinuxProfilesFromPod returns the SELinux types of the pod which can
// belong to a SelinuxProfile or RawSelinuxProfile. It looks first at the pod
// spec level, then in each container.
func getSelinuxProfilesFromPod(pod *corev1.Pod) []string {
	profiles := []string{}
	// try to get profile from pod securityContext
	sc := pod.Spec.SecurityContext
	if sc != nil && isOperatorSelinuxType(sc.SELinuxOptions) {
		profiles = append(profiles, sc.SELinuxOptions.Type)
	}

	// try to get profile(s) from securityContext in containers
	for ctr := range allContainers(pod) {
		sc := ctr.SecurityContext
		if sc != nil && isOperatorSelinuxType(sc.SELinuxOptions) {
			profileString := sc.SELinuxOptions.Type
			if !slices.Contains(profiles, profileString) {
				profiles = append(profiles, profileString)
			}
		}
	}

	return profiles
}

// getAppArmorProfilesFromPod returns the names of the localhost AppArmor
// profiles used by the pod, from the security contexts and the deprecated
// annotations.
func getAppArmorProfilesFromPod(pod *corev1.Pod) []string {
	profiles := []string{}

	add := func(name string) {
		if name != "" && !slices.Contains(profiles, name) {
			profiles = append(profiles, name)
		}
	}

	localhostName := func(profile *corev1.AppArmorProfile) string {
		if profile == nil || profile.Type != corev1.AppArmorProfileTypeLocalhost ||
			profile.LocalhostProfile == nil {
			return ""
		}

		return *profile.LocalhostProfile
	}

	if sc := pod.Spec.SecurityContext; sc != nil {
		add(localhostName(sc.AppArmorProfile))
	}

	for ctr := range allContainers(pod) {
		if sc := ctr.SecurityContext; sc != nil {
			add(localhostName(sc.AppArmorProfile))
		}
	}

	for key, value := range pod.GetAnnotations() {
		if strings.HasPrefix(key, corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix) {
			if name, ok := strings.CutPrefix(
				value,
				corev1.DeprecatedAppArmorBetaProfileNamePrefix,
			); ok {
				add(name)
			}
		}
	}

	slices.Sort(profiles)

	return profiles
}

// isOperatorSeccompProfile checks whether a corev1.SeccompProfile object belongs to the operator.
// SeccompProfiles controlled by the operator are of type "Localhost" and have a path of the form
// "operator/profile-name.json".
func isOperatorSeccompProfile(sp *corev1.SeccompProfile) bool {
	if sp == nil || sp.Type != corev1.SeccompProfileTypeLocalhost || sp.LocalhostProfile == nil {
		return false
	}

	if !strings.HasPrefix(*sp.LocalhostProfile, seccompOperatorDir) {
		return false
	}

	if !strings.HasSuffix(*sp.LocalhostProfile, seccompprofileapi.ExtJSON) {
		return false
	}

	return len(strings.Split(*sp.LocalhostProfile, "/")) == pathParts
}

// isOperatorSelinuxType checks whether the SELinux type can be created by
// the operator. Such types have the form "<profile name>.process". Whether a
// profile with that name exists is checked when the pod gets reconciled, so
// that a pod which starts before its profile is picked up once the profile
// gets created.
func isOperatorSelinuxType(se *corev1.SELinuxOptions) bool {
	if se == nil {
		return false
	}

	name, found := strings.CutSuffix(se.Type, selinuxTypeSuffix)

	return found && name != ""
}
