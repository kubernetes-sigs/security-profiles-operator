/*
Copyright 2020 The Kubernetes Authors.

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

package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	wait = 30 * time.Second

	errGetProfile          = "cannot get profile"
	errSeccompProfileNil   = "seccomp profile cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	reasonSeccompNotSupported   event.Reason = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile event.Reason = "InvalidSeccompProfile"
	reasonCannotGetProfilePath  event.Reason = "CannotGetSeccompProfilePath"
	reasonCannotSaveProfile     event.Reason = "CannotSaveSeccompProfile"
	reasonCannotRemoveProfile   event.Reason = "CannotRemoveSeccompProfile"
	reasonCannotUpdateProfile   event.Reason = "CannotUpdateSeccompProfile"

	reasonSavedProfile event.Reason = "SavedSeccompProfile"

	extJSON = ".json"

	spOwnerKey    = ".metadata.seccompProfileOwner"
	linkedPodsKey = ".metadata.activeWorkloads"
)

func hasSeccompProfile(obj runtime.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return len(getSeccompProfilesFromPod(pod)) > 0
}

// Setup adds a controller that reconciles seccomp profiles.
func Setup(ctx context.Context, mgr ctrl.Manager, l logr.Logger) error {
	// Index Pods using seccomp profiles
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1.Pod{}, spOwnerKey, func(rawObj runtime.Object) []string {
		pod, ok := rawObj.(*corev1.Pod)
		if !ok {
			return []string{}
		}
		return getSeccompProfilesFromPod(pod)
	}); err != nil {
		return errors.Wrap(err, "creating pod index")
	}

	// Index SeccompProfiles with active pods
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &v1alpha1.SeccompProfile{}, linkedPodsKey, func(rawObj runtime.Object) []string {
			sp, ok := rawObj.(*v1alpha1.SeccompProfile)
			if !ok {
				return []string{}
			}
			return sp.Status.ActiveWorkloads
		}); err != nil {
		return errors.Wrap(err, "creating seccomp profile index")
	}

	// Register a special reconciler for pod events
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("pods").
		For(&corev1.Pod{}).
		WithEventFilter(resource.NewPredicates(hasSeccompProfile)).
		Complete(&PodReconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("pods")),
		}); err != nil {
		return errors.Wrap(err, "creating pod controller")
	}
	// Register the regular reconciler to manage SeccompProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&v1alpha1.SeccompProfile{}).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("profile")),
			save:   saveProfileOnDisk,
		})
}

type saver func(string, []byte) error

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
	save   saver
}

// A PodReconciler monitors pod changes and links them to SeccompProfiles.
type PodReconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
}

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		r.record.Event(&v1alpha1.SeccompProfile{},
			event.Warning(reasonSeccompNotSupported, err, os.Getenv(config.NodeNameEnvKey),
				"node does not support seccomp"))

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	seccompProfile := &v1alpha1.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		// Expected to find a SeccompProfile, return an error and requeue
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}

	return r.reconcileSeccompProfile(ctx, seccompProfile, logger)
}

// OutputProfile represents the on-disk form of the SeccompProfile.
type OutputProfile struct {
	DefaultAction seccomp.Action      `json:"defaultAction"`
	Architectures []*v1alpha1.Arch    `json:"architectures,omitempty"`
	Syscalls      []*v1alpha1.Syscall `json:"syscalls,omitempty"`
	Flags         []*v1alpha1.Flag    `json:"flags,omitempty"`
}

func unionSyscalls(baseSyscalls, appliedSyscalls []*v1alpha1.Syscall) []*v1alpha1.Syscall {
	allSyscalls := make(map[seccomp.Action]map[string]bool)
	for _, b := range baseSyscalls {
		allSyscalls[b.Action] = make(map[string]bool)
		for _, n := range b.Names {
			allSyscalls[b.Action][n] = true
		}
	}
	for _, s := range appliedSyscalls {
		if _, ok := allSyscalls[s.Action]; !ok {
			allSyscalls[s.Action] = make(map[string]bool)
		}
		for _, n := range s.Names {
			allSyscalls[s.Action][n] = true
		}
	}
	finalSyscalls := make([]*v1alpha1.Syscall, 0, len(appliedSyscalls)+len(baseSyscalls))
	for action, names := range allSyscalls {
		syscall := v1alpha1.Syscall{Action: action}
		for n := range names {
			syscall.Names = append(syscall.Names, n)
		}
		finalSyscalls = append(finalSyscalls, &syscall)
	}
	return finalSyscalls
}

func (r *Reconciler) mergeBaseProfile(
	ctx context.Context, sp *v1alpha1.SeccompProfile, l logr.Logger,
) (OutputProfile, error) {
	op := OutputProfile{
		DefaultAction: sp.Spec.DefaultAction,
		Architectures: sp.Spec.Architectures,
		Flags:         sp.Spec.Flags,
	}
	baseProfileName := sp.Spec.BaseProfileName
	if baseProfileName == "" {
		op.Syscalls = sp.Spec.Syscalls
		return op, nil
	}
	baseProfile := &v1alpha1.SeccompProfile{}
	if err := r.client.Get(
		ctx, namespacedName(baseProfileName, sp.GetNamespace()), baseProfile); err != nil {
		l.Error(err, "cannot retrieve base profile "+baseProfileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return op, errors.Wrap(err, "cannot retrieve base profile")
	}
	op.Syscalls = unionSyscalls(baseProfile.Spec.Syscalls, sp.Spec.Syscalls)
	return op, nil
}

func (r *Reconciler) reconcileSeccompProfile(
	ctx context.Context, sp *v1alpha1.SeccompProfile, l logr.Logger) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errors.New(errSeccompProfileNil)
	}
	profileName := sp.Name

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	profileContent, err := json.Marshal(outputProfile)
	if err != nil {
		l.Error(err, "cannot validate profile "+profileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	profilePath, err := GetProfilePath(profileName, sp.ObjectMeta.Namespace, sp.Spec.TargetWorkload)
	if err != nil {
		l.Error(err, "cannot get profile path")
		r.record.Event(sp, event.Warning(reasonCannotGetProfilePath, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	nodeFinalizerString := os.Getenv(config.NodeNameEnvKey) + "-delete"
	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		status := sp.Status
		status.Status = "Terminating"
		if err = r.setStatus(ctx, sp, &status); err != nil {
			l.Error(err, "cannot update SeccompProfile status")
			r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
			return reconcile.Result{}, errors.Wrap(err, "updating status")
		}
		if !controllerutil.ContainsFinalizer(sp, nodeFinalizerString) {
			return ctrl.Result{}, nil
		}
		if err := handleDeletion(sp, l); err != nil {
			l.Error(err, "cannot delete profile")
			r.record.Event(sp, event.Warning(reasonCannotRemoveProfile, err))
			return ctrl.Result{}, errors.Wrap(err, "deleting profile")
		}
		if err := retry(func() error {
			return removeFinalizer(ctx, r.client, sp, nodeFinalizerString)
		}, kerrors.IsConflict); err != nil {
			l.Error(err, "cannot remove finalizer from seccomp profile")
			r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
			return ctrl.Result{}, errors.Wrap(err, "deleting finalizer")
		}
		return ctrl.Result{}, nil
	}
	if err := retry(func() error {
		return addFinalizer(ctx, r.client, sp, nodeFinalizerString)
	}, kerrors.IsConflict); err != nil {
		l.Error(err, "cannot update SeccompProfile finalizers")
		r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "adding finalizer")
	}
	if err = r.save(profilePath, profileContent); err != nil {
		l.Error(err, "cannot save profile into disk")
		r.record.Event(sp, event.Warning(reasonCannotSaveProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	// refresh reference
	if err := r.client.Get(ctx, namespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}
	status := sp.Status
	status.Path = profilePath
	status.Status = "Active"
	status.LocalhostProfile = strings.TrimPrefix(profilePath, config.KubeletSeccompRootPath+"/")
	if err = r.setStatus(ctx, sp, &status); err != nil {
		l.Error(err, "cannot update SeccompProfile status")
		r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "updating status")
	}
	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	r.record.Event(sp, event.Normal(reasonSavedProfile, "Successfully saved profile to disk"))
	return reconcile.Result{}, nil
}

// setStatus checks if the Status of a SeccompProfile is in sync with the supplied
// SeccompProfileStatus and updates the SeccompProfile if not.
func (r *Reconciler) setStatus(
	ctx context.Context, sp *v1alpha1.SeccompProfile, status *v1alpha1.SeccompProfileStatus) error {
	if sp.Status.Status == status.Status &&
		sp.Status.Path == status.Path &&
		sp.Status.LocalhostProfile == status.LocalhostProfile {
		return nil
	}
	sp.Status = *status
	if err := r.client.Status().Update(ctx, sp); err != nil {
		return errors.Wrap(err, "setting status")
	}
	return nil
}

// Reconcile reacts to pod events and updates SeccompProfiles if in use or no longer in use by a pod.
func (r *PodReconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	podID := req.Namespace + "/" + req.Name

	pod := &corev1.Pod{}
	var err error
	if err = r.client.Get(ctx, req.NamespacedName, pod); ignoreNotFound(err) != nil {
		logger.Error(err, "could not get pod")
		return reconcile.Result{}, errors.Wrap(err, "looking up pod")
	}
	if kerrors.IsNotFound(err) { // this is a pod deletion, so update all seccomp profiles that were using it
		seccompProfiles := &v1alpha1.SeccompProfileList{}
		if err = r.client.List(ctx, seccompProfiles, client.MatchingFields{linkedPodsKey: podID}); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "listing SeccompProfiles")
		}
		for i := range seccompProfiles.Items {
			if err = r.updatePodReferences(ctx, &seccompProfiles.Items[i]); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile")
			}
		}
		return reconcile.Result{}, nil
	}
	// pod is being created or updated so ensure it is linked to a seccomp profile
	for _, profileIndex := range getSeccompProfilesFromPod(pod) {
		profileElements := strings.Split(profileIndex, "/")
		profileNamespace := profileElements[1]
		profileName := strings.TrimSuffix(profileElements[3], ".json")
		seccompProfile := &v1alpha1.SeccompProfile{}
		if err := r.client.Get(ctx, namespacedName(profileName, profileNamespace), seccompProfile); err != nil {
			logger.Error(err, "could not get seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "looking up SeccompProfile")
		}
		if err := r.updatePodReferences(ctx, seccompProfile); err != nil {
			logger.Error(err, "could not update seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile")
		}
	}
	return reconcile.Result{}, nil
}

// updatePodReferences updates a SeccompProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferences(ctx context.Context, sp *v1alpha1.SeccompProfile) error {
	linkedPods := &corev1.PodList{}
	profileReference := fmt.Sprintf("operator/%s/%s/%s.json", sp.GetNamespace(), sp.Spec.TargetWorkload, sp.GetName())
	err := r.client.List(ctx, linkedPods, client.MatchingFields{spOwnerKey: profileReference})
	if ignoreNotFound(err) != nil {
		return errors.Wrap(err, "listing pods")
	}
	podList := make([]string, len(linkedPods.Items))
	for i := range linkedPods.Items {
		pod := linkedPods.Items[i]
		podList[i] = pod.ObjectMeta.Namespace + "/" + pod.ObjectMeta.Name
	}
	sp.Status.ActiveWorkloads = podList
	if err := r.client.Status().Update(ctx, sp); err != nil {
		return errors.Wrap(err, "updating SeccompProfile")
	}
	hasActivePodsFinalizerString := "in-use-by-active-pods"
	if len(linkedPods.Items) > 0 {
		if err := retry(func() error {
			return addFinalizer(ctx, r.client, sp, hasActivePodsFinalizerString)
		}, kerrors.IsConflict); err != nil {
			return err
		}
	} else {
		if err := retry(func() error {
			return removeFinalizer(ctx, r.client, sp, hasActivePodsFinalizerString)
		}, kerrors.IsConflict); err != nil {
			return err
		}
	}
	return nil
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
	containers := append(pod.Spec.Containers, pod.Spec.InitContainers...)
	contains := func(a []string, b string) bool {
		for _, s := range a {
			if s == b {
				return true
			}
		}
		return false
	}
	for i := range containers {
		sc := containers[i].SecurityContext
		if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
			profileString := *containers[i].SecurityContext.SeccompProfile.LocalhostProfile
			if !contains(profiles, profileString) {
				profiles = append(profiles, profileString)
			}
		}
	}
	// try to get profile from annotations
	annotation, hasAnnotation := pod.GetAnnotations()[corev1.SeccompPodAnnotationKey]
	if hasAnnotation && strings.HasPrefix(annotation, "localhost/") {
		profileString := strings.TrimPrefix(annotation, "localhost/")
		if !contains(profiles, profileString) {
			profiles = append(profiles, profileString)
		}
	}
	return profiles
}

// isOperatorSeccompProfile checks whether a corev1.SeccompProfile object belongs to the operator.
// SeccompProfiles controlled by the operator are of type "Localhost" and have a path of the form
// "operator/namespace/workload-group/profile-name.json".
func isOperatorSeccompProfile(sp *corev1.SeccompProfile) bool {
	if sp == nil || sp.Type != "Localhost" {
		return false
	}
	if !strings.HasPrefix(*sp.LocalhostProfile, "operator/") {
		return false
	}
	if !strings.HasSuffix(*sp.LocalhostProfile, ".json") {
		return false
	}
	pathParts := 4
	return len(strings.Split(*sp.LocalhostProfile, "/")) == pathParts
}

// retry attempts to execute fn up to 5 times if its failure meets retryCondition.
func retry(fn func() error, retryCondition func(error) bool) error {
	const retries = 5
	var err error
	for i := 0; i < retries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if !retryCondition(err) {
			return errors.Wrap(err, "failed retry")
		}
	}
	return errors.Wrap(err, fmt.Sprintf("exceeded %d retries", retries))
}

// addFinalizer attempts to add a finalizer to an object if not present and update the object.
func addFinalizer(ctx context.Context, c client.Client, sp *v1alpha1.SeccompProfile, finalizer string) error {
	// Refresh object
	if err := c.Get(ctx, namespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
		return errors.Wrap(err, "retrieving sp")
	}
	if controllerutil.ContainsFinalizer(sp, finalizer) {
		return nil
	}
	controllerutil.AddFinalizer(sp, finalizer)
	return c.Update(ctx, sp)
}

// removeFinalizer attempts to remove a finalizer from an object if present and update the object.
func removeFinalizer(ctx context.Context, c client.Client, sp *v1alpha1.SeccompProfile, finalizer string) error {
	// Refresh object
	if err := c.Get(ctx, namespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
		return errors.Wrap(err, "retrieving sp")
	}
	if !controllerutil.ContainsFinalizer(sp, finalizer) {
		return nil
	}
	controllerutil.RemoveFinalizer(sp, finalizer)
	return c.Update(ctx, sp)
}

func handleDeletion(sp *v1alpha1.SeccompProfile, l logr.Logger) error {
	profilePath, err := GetProfilePath(sp.GetName(), sp.GetNamespace(), sp.Spec.TargetWorkload)
	if err != nil {
		return err
	}
	err = os.Remove(profilePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "deleting profile from host")
	}
	l.Info(fmt.Sprintf("removed profile %s", profilePath))
	return nil
}

func saveProfileOnDisk(fileName string, contents []byte) error {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return errors.Wrap(err, errCreatingOperatorDir)
	}

	if err := ioutil.WriteFile(fileName, contents, filePermissionMode); err != nil {
		return errors.Wrap(err, errSavingProfile)
	}
	return nil
}

// GetProfilePath returns the full path for the provided profile name and config.
func GetProfilePath(profileName, namespace, subdir string) (string, error) {
	if filepath.Ext(profileName) != extJSON {
		profileName += extJSON
	}
	return path.Join(
		config.ProfilesRootPath,
		filepath.Base(namespace),
		filepath.Base(subdir),
		filepath.Base(profileName),
	), nil
}

func namespacedName(name, namespace string) types.NamespacedName {
	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}
