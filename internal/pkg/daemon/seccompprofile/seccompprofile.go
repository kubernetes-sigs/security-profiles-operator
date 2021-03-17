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

package seccompprofile

import (
	"bytes"
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
	rcommonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	shortWait = 2 * time.Second
	wait      = 30 * time.Second

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
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1.Pod{}, spOwnerKey, func(rawObj client.Object) []string {
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
		ctx, &v1alpha1.SeccompProfile{}, linkedPodsKey, func(rawObj client.Object) []string {
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

type saver func(string, []byte) (bool, error)

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

// Security Profiles Operator RBAC permissions to manage SeccompProfile
// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// OpenShift ... This is ignored in other distros
// nolint:lll
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resources=securitycontextconstraints,verbs=use

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		if r.record != nil {
			r.record.Event(&v1alpha1.SeccompProfile{},
				event.Warning(reasonSeccompNotSupported, err, os.Getenv(config.NodeNameEnvKey),
					"node does not support seccomp"))
		}

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
		ctx, util.NamespacedName(baseProfileName, sp.GetNamespace()), baseProfile); err != nil {
		l.Error(err, "cannot retrieve base profile "+baseProfileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return op, errors.Wrap(err, "merging base profile")
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

	nodeStatus, err := nodestatus.NewForProfile(sp)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus")
	}

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

	profilePath, err := GetProfilePath(profileName, sp.ObjectMeta.Namespace)
	if err != nil {
		l.Error(err, "cannot get profile path")
		r.record.Event(sp, event.Warning(reasonCannotGetProfilePath, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		setTerminatingStatus := func(sp *v1alpha1.SeccompProfile) *v1alpha1.SeccompProfileStatus {
			status := sp.Status.DeepCopy()
			status.SetConditions(rcommonv1.Deleting())
			status.Status = secprofnodestatusv1alpha1.ProfileStateTerminating
			return status
		}

		if err := r.setBothStatuses(ctx, nodeStatus, sp, setTerminatingStatus); err != nil {
			l.Error(err, "cannot update SeccompProfile status")
			r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
			return reconcile.Result{}, errors.Wrap(err, "updating status for deleted SeccompProfile")
		}

		hasStatus, err := nodeStatus.Exists(ctx, r.client)
		if err != nil || !hasStatus {
			return ctrl.Result{}, errors.Wrap(err, "checking if node status exists")
		}

		if err := handleDeletion(sp, l); err != nil {
			l.Error(err, "cannot delete profile")
			r.record.Event(sp, event.Warning(reasonCannotRemoveProfile, err))
			return ctrl.Result{}, errors.Wrap(err, "handling file deletion for deleted SeccompProfile")
		}

		if err := nodeStatus.Remove(ctx, r.client); err != nil {
			l.Error(err, "cannot remove node status/finalizer from seccomp profile")
			r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
			return ctrl.Result{}, errors.Wrap(err, "deleting node status/finalizer for deleted SeccompProfile")
		}
		return ctrl.Result{}, nil
	}

	hasNodeStatus, err := r.ensureNodeStatus(ctx, nodeStatus, sp)
	if err != nil {
		l.Error(err, "cannot create SeccompProfile status/finalizers")
		r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "adding status/finalizer for SeccompProfile")
	}

	if !hasNodeStatus {
		l.Info("profile node status created, reconciling")
		return reconcile.Result{RequeueAfter: shortWait}, nil
	}

	updated, err := r.save(profilePath, profileContent)
	if err != nil {
		l.Error(err, "cannot save profile into disk")
		r.record.Event(sp, event.Warning(reasonCannotSaveProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	// refresh reference
	if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}

	setInstalledStatus := func(sp *v1alpha1.SeccompProfile) *v1alpha1.SeccompProfileStatus {
		status := sp.Status.DeepCopy()
		status.Path = profilePath
		status.SetConditions(rcommonv1.Available())
		status.Status = secprofnodestatusv1alpha1.ProfileStateInstalled
		status.LocalhostProfile = strings.TrimPrefix(profilePath, config.KubeletSeccompRootPath+"/")
		return status
	}

	if err := r.setBothStatuses(ctx, nodeStatus, sp, setInstalledStatus); err != nil {
		l.Error(err, "cannot update SeccompProfile status")
		r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "updating status in SeccompProfile reconciler")
	}

	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	if updated {
		evstr := fmt.Sprintf("Successfully saved profile to disk on %s", os.Getenv(config.NodeNameEnvKey))
		r.record.Event(sp, event.Normal(reasonSavedProfile, evstr))
	}
	return reconcile.Result{}, nil
}

// setBothStatuses checks if the node status of a SeccompProfile is in sync with the supplied
// SeccompProfileStatus and updates the node status if not. Additionally, the status of the
// SeccompProfile is set to the lowest common denominator as well.
func (r *Reconciler) setBothStatuses(
	ctx context.Context, ns *nodestatus.StatusClient,
	sp *v1alpha1.SeccompProfile, setStatusFn func(sp *v1alpha1.SeccompProfile) *v1alpha1.SeccompProfileStatus,
) error {
	if retryErr := util.Retry(func() error {
		if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
			return errors.Wrap(err, "retrieving profile")
		}

		status := setStatusFn(sp)

		profileStatus, err := ns.SetReturnGlobal(ctx, r.client, status.Status)
		if err != nil {
			return errors.Wrap(err, "setting per-node status")
		}
		status.Status = profileStatus
		return r.setStatus(ctx, sp, status)
	}, util.IsNotFoundOrConflict); retryErr != nil {
		return errors.Wrap(retryErr, "updating profile status")
	}

	return nil
}

func (r *Reconciler) ensureNodeStatus(
	ctx context.Context, nodeStatus *nodestatus.StatusClient, sp *v1alpha1.SeccompProfile) (bool, error) {
	nodeStatusExists, err := nodeStatus.Exists(ctx, r.client)
	if err != nil {
		return false, errors.Wrap(err, "Retrieving node status")
	}

	if !nodeStatusExists {
		if err := nodeStatus.Create(ctx, r.client); err != nil {
			return nodeStatusExists, errors.Wrap(err, "Creating node status")
		}
	}

	if err := util.Retry(func() error {
		if sp.Status.Status != "" {
			return nil
		}

		profileCopy := sp.DeepCopy()
		profileCopy.Status.Status = secprofnodestatusv1alpha1.ProfileStatePending
		profileCopy.Status.SetConditions(rcommonv1.Creating())

		updateErr := r.client.Status().Update(context.TODO(), profileCopy)
		if updateErr != nil {
			if err := r.client.Get(
				ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
				return errors.Wrap(err, "retrieving profile")
			}
		}
		return errors.Wrap(updateErr, "updating to initial state")
	}, util.IsNotFoundOrConflict); err != nil {
		return nodeStatusExists, errors.Wrap(err, "Updating seccomp status to PENDING")
	}

	return nodeStatusExists, nil
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
		return errors.Wrap(err, "setting SeccompProfile status")
	}
	return nil
}

// Namespace scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile reacts to pod events and updates SeccompProfiles if in use or no longer in use by a pod.
func (r *PodReconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	podID := req.Namespace + "/" + req.Name

	pod := &corev1.Pod{}
	var err error
	if err = r.client.Get(ctx, req.NamespacedName, pod); ignoreNotFound(err) != nil {
		logger.Error(err, "could not get pod")
		return reconcile.Result{}, errors.Wrap(err, "looking up pod in pod reconciler")
	}
	if kerrors.IsNotFound(err) { // this is a pod deletion, so update all seccomp profiles that were using it
		seccompProfiles := &v1alpha1.SeccompProfileList{}
		if err = r.client.List(ctx, seccompProfiles, client.MatchingFields{linkedPodsKey: podID}); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "listing SeccompProfiles for deleted pod")
		}
		for i := range seccompProfiles.Items {
			if err = r.updatePodReferences(ctx, &seccompProfiles.Items[i]); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile for deleted pod")
			}
		}
		return reconcile.Result{}, nil
	}
	// pod is being created or updated so ensure it is linked to a seccomp profile
	for _, profileIndex := range getSeccompProfilesFromPod(pod) {
		profileElements := strings.Split(profileIndex, "/")
		profileNamespace := profileElements[1]
		profileName := strings.TrimSuffix(profileElements[2], ".json")
		seccompProfile := &v1alpha1.SeccompProfile{}
		if err := r.client.Get(ctx, util.NamespacedName(profileName, profileNamespace), seccompProfile); err != nil {
			logger.Error(err, "could not get seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "looking up SeccompProfile for new or updated pod")
		}
		if err := r.updatePodReferences(ctx, seccompProfile); err != nil {
			logger.Error(err, "could not update seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile pod references for new or updated pod")
		}
	}
	return reconcile.Result{}, nil
}

// updatePodReferences updates a SeccompProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferences(ctx context.Context, sp *v1alpha1.SeccompProfile) error {
	linkedPods := &corev1.PodList{}
	profileReference := fmt.Sprintf("operator/%s/%s.json", sp.GetNamespace(), sp.GetName())
	err := r.client.List(ctx, linkedPods, client.MatchingFields{spOwnerKey: profileReference})
	if ignoreNotFound(err) != nil {
		return errors.Wrap(err, "listing pods to update seccompProfile")
	}
	podList := make([]string, len(linkedPods.Items))
	for i := range linkedPods.Items {
		pod := linkedPods.Items[i]
		podList[i] = pod.ObjectMeta.Namespace + "/" + pod.ObjectMeta.Name
	}
	if err := util.Retry(func() error {
		sp.Status.ActiveWorkloads = podList

		updateErr := r.client.Status().Update(ctx, sp)
		if updateErr != nil {
			if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
				return errors.Wrap(err, "retrieving profile")
			}
		}

		return errors.Wrap(updateErr, "updating profile")
	}, util.IsNotFoundOrConflict); err != nil {
		return errors.Wrap(err, "updating SeccompProfile status")
	}
	hasActivePodsFinalizerString := "in-use-by-active-pods"
	if len(linkedPods.Items) > 0 {
		if err := util.Retry(func() error {
			return util.AddFinalizer(ctx, r.client, sp, hasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return errors.Wrap(err, "adding finalizer")
		}
	} else {
		if err := util.Retry(func() error {
			return util.RemoveFinalizer(ctx, r.client, sp, hasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return errors.Wrap(err, "removing finalizer")
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
// "operator/namespace/profile-name.json".
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
	const pathParts = 3
	return len(strings.Split(*sp.LocalhostProfile, "/")) == pathParts
}

func handleDeletion(sp *v1alpha1.SeccompProfile, l logr.Logger) error {
	profilePath, err := GetProfilePath(sp.GetName(), sp.GetNamespace())
	if err != nil {
		return err
	}
	err = os.Remove(profilePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "removing profile from host")
	}
	l.Info(fmt.Sprintf("removed profile %s", profilePath))
	return nil
}

func saveProfileOnDisk(fileName string, content []byte) (updated bool, err error) {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return false, errors.Wrap(err, errCreatingOperatorDir)
	}

	existingContent, err := ioutil.ReadFile(fileName)
	if err == nil && bytes.Equal(existingContent, content) {
		return false, nil
	}

	if err := ioutil.WriteFile(fileName, content, filePermissionMode); err != nil {
		return false, errors.Wrap(err, errSavingProfile)
	}

	return true, nil
}

// GetProfilePath returns the full path for the provided profile name and config.
func GetProfilePath(profileName, namespace string) (string, error) {
	if filepath.Ext(profileName) != extJSON {
		profileName += extJSON
	}
	return path.Join(
		config.ProfilesRootPath,
		filepath.Base(namespace),
		filepath.Base(profileName),
	), nil
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}
