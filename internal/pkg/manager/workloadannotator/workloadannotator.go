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
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
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
	// inUseKey indexes profiles by whether they carry the in-use finalizer.
	inUseKey         = ".metadata.inUse"
	inUseValue       = "true"
	reconcileTimeout = 1 * time.Minute
	pathParts        = 2

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

	err := r.client.Get(ctx, req.NamespacedName, pod)
	if kerrors.IsNotFound(err) {
		return reconcile.Result{}, r.handlePodDeletion(ctx, req.Namespace+"/"+req.Name)
	}

	if err != nil {
		logger.Error(err, "could not get pod")

		return reconcile.Result{}, fmt.Errorf("looking up pod in pod reconciler: %w", err)
	}

	if err := r.handlePodUpdate(ctx, logger, pod); err != nil {
		r.record.Eventf(
			pod, nil, corev1.EventTypeWarning, reasonReconcileErr, util.EventActionReconcile,
			"%s", err.Error(),
		)

		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// handlePodDeletion updates all profiles which were used by the deleted pod.
func (r *PodReconciler) handlePodDeletion(ctx context.Context, podID string) error {
	// Every profile kind is released on its own, so that a failure with one
	// kind does not keep the profiles of the other kinds in use.
	errs := []error{
		r.releaseSeccompProfiles(ctx, podID),
		r.releaseSelinuxProfiles(ctx, podID),
		r.releaseAppArmorProfiles(ctx),
		r.releaseRawSelinuxProfiles(ctx),
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("updating profiles for deleted pod: %w", err)
	}

	return nil
}

func (r *PodReconciler) releaseSeccompProfiles(ctx context.Context, podID string) error {
	profiles := &seccompprofileapi.SeccompProfileList{}
	if err := r.client.List(
		ctx, profiles, client.MatchingFields{linkedPodsKey: podID},
	); err != nil {
		return fmt.Errorf("listing SeccompProfiles for deleted pod: %w", err)
	}

	errs := make([]error, 0, len(profiles.Items))
	for i := range profiles.Items {
		errs = append(errs, r.updatePodReferencesForSeccomp(ctx, &profiles.Items[i]))
	}

	return errors.Join(errs...)
}

func (r *PodReconciler) releaseSelinuxProfiles(ctx context.Context, podID string) error {
	profiles := &selinuxprofileapi.SelinuxProfileList{}
	if err := r.client.List(
		ctx, profiles, client.MatchingFields{linkedPodsKey: podID},
	); err != nil {
		return fmt.Errorf("listing SelinuxProfiles for deleted pod: %w", err)
	}

	errs := make([]error, 0, len(profiles.Items))
	for i := range profiles.Items {
		errs = append(errs, r.updatePodReferencesForSelinux(ctx, &profiles.Items[i]))
	}

	return errors.Join(errs...)
}

// releaseAppArmorProfiles checks every AppArmorProfile in use again, because
// the kind has no list of active workloads. The index keeps the profiles
// nobody uses out of the listing.
func (r *PodReconciler) releaseAppArmorProfiles(ctx context.Context) error {
	profiles := &apparmorprofileapi.AppArmorProfileList{}
	if err := r.client.List(
		ctx, profiles, client.MatchingFields{inUseKey: inUseValue},
	); err != nil {
		return fmt.Errorf("listing AppArmorProfiles for deleted pod: %w", err)
	}

	errs := make([]error, 0, len(profiles.Items))
	for i := range profiles.Items {
		if isInUse(&profiles.Items[i]) {
			errs = append(errs, r.updatePodReferencesForAppArmor(ctx, &profiles.Items[i]))
		}
	}

	return errors.Join(errs...)
}

// releaseRawSelinuxProfiles checks every RawSelinuxProfile in use again, like
// releaseAppArmorProfiles.
func (r *PodReconciler) releaseRawSelinuxProfiles(ctx context.Context) error {
	profiles := &selinuxprofileapi.RawSelinuxProfileList{}
	if err := r.client.List(
		ctx, profiles, client.MatchingFields{inUseKey: inUseValue},
	); err != nil {
		return fmt.Errorf("listing RawSelinuxProfiles for deleted pod: %w", err)
	}

	errs := make([]error, 0, len(profiles.Items))
	for i := range profiles.Items {
		if isInUse(&profiles.Items[i]) {
			errs = append(errs, r.updatePodReferencesForRawSelinux(ctx, &profiles.Items[i]))
		}
	}

	return errors.Join(errs...)
}

func isInUse(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, util.HasActivePodsFinalizerString)
}

// inUseIndex indexes profiles which carry the in-use finalizer.
func inUseIndex(obj client.Object) []string {
	if isInUse(obj) {
		return []string{inUseValue}
	}

	return nil
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

// updatePodReferences updates a profile with the identifiers of the pods using
// it and ensures it carries a finalizer indicating it is in use, so that it
// cannot be deleted from under a running workload. It is shared by every
// profile kind: the kinds differ only in how pods reference them and in where
// the active workload list lives. Kinds without a list of active workloads
// pass nil accessors.
func updatePodReferences[T client.Object](
	ctx context.Context,
	r *PodReconciler,
	prof T,
	kind, ownerKey, profileReference string,
	getActiveWorkloads func(T) []string,
	setActiveWorkloads func(T, []string),
) error {
	linkedPods := &corev1.PodList{}

	err := r.client.List(ctx, linkedPods, client.MatchingFields{ownerKey: profileReference})
	if util.IgnoreNotFound(err) != nil {
		return fmt.Errorf("listing pods to update %s: %w", kind, err)
	}

	podList := make([]string, len(linkedPods.Items))

	for i := range linkedPods.Items {
		pod := &linkedPods.Items[i]
		podList[i] = pod.Namespace + "/" + pod.Name
	}

	slices.Sort(podList)

	profileDeleted := false

	if err := util.Retry(func() error {
		if err := r.reader.Get(
			ctx,
			util.NamespacedName(prof.GetName(), prof.GetNamespace()),
			prof,
		); err != nil {
			if kerrors.IsNotFound(err) {
				profileDeleted = true

				return nil
			}

			return fmt.Errorf("retrieving profile: %w", err)
		}

		if getActiveWorkloads == nil || sameActiveWorkloads(getActiveWorkloads(prof), podList) {
			return nil
		}

		setActiveWorkloads(prof, slices.Clone(podList))

		if err := r.client.Status().Update(ctx, prof); err != nil {
			return fmt.Errorf("updating profile: %w", err)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating %s status: %w", kind, err)
	}

	if profileDeleted {
		return nil
	}

	if len(linkedPods.Items) > 0 {
		if err := util.Retry(func() error {
			return client.IgnoreNotFound(
				util.AddFinalizer(ctx, r.client, prof, util.HasActivePodsFinalizerString),
			)
		}, util.IsNotFoundOrConflict); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}

		return nil
	}

	if err := util.Retry(func() error {
		return client.IgnoreNotFound(
			util.RemoveFinalizer(ctx, r.client, prof, util.HasActivePodsFinalizerString),
		)
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	return nil
}

// seccompProfileReference returns the localhost profile path of the profile,
// as pods reference it.
func seccompProfileReference(sp *seccompprofileapi.SeccompProfile) string {
	return seccompOperatorDir + sp.GetProfileFile()
}

// updatePodReferencesForSeccomp updates a SeccompProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferencesForSeccomp(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
) error {
	return updatePodReferences(
		ctx, r, sp,
		"seccompProfile", spOwnerKey, seccompProfileReference(sp),
		func(p *seccompprofileapi.SeccompProfile) []string { return p.Status.ActiveWorkloads },
		func(p *seccompprofileapi.SeccompProfile, w []string) { p.Status.ActiveWorkloads = w },
	)
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

// updatePodReferencesForSelinux updates a SelinuxProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferencesForSelinux(
	ctx context.Context,
	se *selinuxprofileapi.SelinuxProfile,
) error {
	return updatePodReferences(
		ctx, r, se,
		"selinuxProfile", seOwnerKey, se.GetPolicyUsage(),
		func(p *selinuxprofileapi.SelinuxProfile) []string { return p.Status.ActiveWorkloads },
		func(p *selinuxprofileapi.SelinuxProfile, w []string) { p.Status.ActiveWorkloads = w },
	)
}

// updatePodReferencesForRawSelinux ensures that a RawSelinuxProfile used by
// pods has a finalizer which prevents it from being deleted.
func (r *PodReconciler) updatePodReferencesForRawSelinux(
	ctx context.Context,
	se *selinuxprofileapi.RawSelinuxProfile,
) error {
	return updatePodReferences[*selinuxprofileapi.RawSelinuxProfile](
		ctx, r, se, "rawSelinuxProfile", seOwnerKey, se.GetPolicyUsage(), nil, nil,
	)
}

// updatePodReferencesForAppArmor ensures that an AppArmorProfile used by pods
// has a finalizer which prevents it from being deleted.
func (r *PodReconciler) updatePodReferencesForAppArmor(
	ctx context.Context,
	aa *apparmorprofileapi.AppArmorProfile,
) error {
	return updatePodReferences[*apparmorprofileapi.AppArmorProfile](
		ctx, r, aa, "appArmorProfile", aaOwnerKey, aa.GetProfileName(), nil, nil,
	)
}

// profileReleaser reconciles AppArmorProfiles and RawSelinuxProfiles, which
// have no list of active workloads. If the last pod using such a profile went
// away while the operator did not run, no pod event releases the profile, so
// the profile itself gets checked.
type profileReleaser[T client.Object] struct {
	pods    *PodReconciler
	newObj  func() T
	release func(context.Context, *PodReconciler, T) error
}

func (p *profileReleaser[T]) Reconcile(
	ctx context.Context, req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	profile := p.newObj()
	if err := p.pods.client.Get(ctx, req.NamespacedName, profile); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	if !isInUse(profile) {
		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, p.release(ctx, p.pods, profile)
}

// allContainers returns the regular, init and ephemeral containers of the pod.
func allContainers(pod *corev1.Pod) []corev1.Container {
	containers := slices.Clone(pod.Spec.Containers)
	containers = append(containers, pod.Spec.InitContainers...)

	for i := range pod.Spec.EphemeralContainers {
		containers = append(containers,
			corev1.Container(pod.Spec.EphemeralContainers[i].EphemeralContainerCommon))
	}

	return containers
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
	containers := allContainers(pod)
	for i := range containers {
		sc := containers[i].SecurityContext
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
	containers := allContainers(pod)
	for i := range containers {
		sc := containers[i].SecurityContext
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

	containers := allContainers(pod)
	for i := range containers {
		if sc := containers[i].SecurityContext; sc != nil {
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
