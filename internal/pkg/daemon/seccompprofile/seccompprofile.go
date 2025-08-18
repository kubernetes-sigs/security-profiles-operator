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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/artifact"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 5 * time.Minute

	wait = 10 * time.Second

	errGetProfile          = "cannot get profile"
	errSeccompProfileNil   = "seccomp profile cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"
	errForbiddenSyscall    = "syscall not allowed"
	errForbiddenProfile    = "seccomp profile not allowed"
	errForbiddenAction     = "seccomp action not allowed"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	reasonSeccompNotSupported   string = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile string = "InvalidSeccompProfile"
	reasonCannotPullProfile     string = "CannotPullSeccompProfile"
	reasonCannotSaveProfile     string = "CannotSaveSeccompProfile"
	reasonCannotRemoveProfile   string = "CannotRemoveSeccompProfile"
	reasonCannotUpdateProfile   string = "CannotUpdateSeccompProfile"
	reasonCannotUpdateStatus    string = "CannotUpdateNodeStatus"
	reasonProfileNotAllowed     string = "ProfileNotAllowed"
	reasonSavedProfile          string = "SavedSeccompProfile"

	defaultCacheTimeout time.Duration = 24 * time.Hour
	maxCacheItems       uint64        = 1000
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{
		impl: &defaultImpl{},
		baseProfiles: ttlcache.New(
			ttlcache.WithTTL[string, *seccompprofileapi.SeccompProfile](defaultCacheTimeout),
			ttlcache.WithCapacity[string, *seccompprofileapi.SeccompProfile](maxCacheItems),
		),
	}
}

type saver func(string, []byte) (bool, error)

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	impl
	client       client.Client
	log          logr.Logger
	record       record.EventRecorder
	save         saver
	metrics      *metrics.Metrics
	baseProfiles *ttlcache.Cache[string, *seccompprofileapi.SeccompProfile]
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "seccomp-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() *scheme.Builder {
	return seccompprofileapi.SchemeBuilder
}

// AllowedSyscallsChangedPredicate implements a update predicate function on SPOD's AllowedSyscalls changed.
type AllowedSyscallsChangedPredicate struct {
	predicate.Funcs
}

// Update implements default update event filter for checking SPOD's AllowedSyscalls change.
func (AllowedSyscallsChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	oldSpod, ok := e.ObjectOld.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	newSpod, ok := e.ObjectNew.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	if len(newSpod.Spec.AllowedSyscalls) != len(oldSpod.Spec.AllowedSyscalls) {
		return true
	}

	diff := make(map[string]int, len(newSpod.Spec.AllowedSyscalls))
	for _, s := range newSpod.Spec.AllowedSyscalls {
		diff[s]++
	}

	for _, s := range oldSpod.Spec.AllowedSyscalls {
		if _, ok := diff[s]; !ok {
			return true
		}

		diff[s]--
		if diff[s] == 0 {
			delete(diff, s)
		}
	}

	return len(diff) != 0
}

// Setup adds a controller that reconciles seccomp profiles.
func (r *Reconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = mgr.GetEventRecorderFor("profile")
	r.save = saveProfileOnDisk
	r.metrics = met

	// Register the regular reconciler to manage SeccompProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&seccompprofileapi.SeccompProfile{}).
		Watches(
			&spodapi.SecurityProfilesOperatorDaemon{},
			handler.EnqueueRequestsFromMapFunc(r.handleAllowedSyscallsChanged),
			builder.WithPredicates(AllowedSyscallsChangedPredicate{}),
		).
		Complete(r)
}

func (r *Reconciler) handleAllowedSyscallsChanged(ctx context.Context, obj client.Object) []reconcile.Request {
	spod, ok := obj.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		r.log.Info("cannot handle allowedSyscalls changed for no SPOD objects")

		return []reconcile.Request{}
	}

	if len(spod.Spec.AllowedSyscalls) == 0 {
		return []reconcile.Request{}
	}

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	seccompProfileList := &seccompprofileapi.SeccompProfileList{}
	if err := r.client.List(ctx, seccompProfileList, &client.ListOptions{}); err != nil {
		r.log.Error(err, "cannot list seccomp profiles in the cluster")

		return []reconcile.Request{}
	}

	reconcileRequests := []reconcile.Request{}

	for i := range seccompProfileList.Items {
		sp := &seccompProfileList.Items[i]
		if err := allowProfile(sp, spod.Spec.AllowedSyscalls, spod.Spec.AllowedSeccompActions); err != nil {
			r.log.Info(fmt.Sprintf("deleting not allowed seccomp profile %s/%s",
				sp.GetNamespace(), sp.GetName()))

			if err := r.client.Delete(ctx, sp, &client.DeleteOptions{}); err != nil {
				r.log.Error(err, "cannot delete not allowed seccomp profile")

				continue
			}

			reconcileRequests = append(reconcileRequests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      sp.GetName(),
					Namespace: sp.GetNamespace(),
				},
			})
		}
	}

	return reconcileRequests
}

// Healthz is the liveness probe endpoint of the controller.
func (r *Reconciler) Healthz(*http.Request) error {
	return r.checkSeccomp()
}

// checkSeccomp verifies if the seccomp is supported by the node.
func (r *Reconciler) checkSeccomp() error {
	if !seccomp.IsSupported() {
		err := errors.New("seccomp not supported")
		err = fmt.Errorf("node %q: %w", os.Getenv(config.NodeNameEnvKey), err)

		if r.record != nil {
			r.metrics.IncSeccompProfileError(reasonSeccompNotSupported)
			r.record.AnnotatedEventf(
				&seccompprofileapi.SeccompProfile{},
				map[string]string{os.Getenv(config.NodeNameEnvKey): "node does not support seccomp"},
				util.EventTypeWarning,
				reasonSeccompNotSupported,
				err.Error())
		}

		return err
	}

	return nil
}

// Security Profiles Operator RBAC permissions to manage SeccompProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;get;patch;update

// OpenShift ... This is ignored in other distros
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resources=securitycontextconstraints,verbs=use

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if err := r.checkSeccomp(); err != nil {
		logger.Error(err, "profile not added")
		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	seccompProfile := &seccompprofileapi.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		// Expected to find a SeccompProfile, return an error and requeue
		if util.IgnoreNotFound(err) == nil {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("%s: %w", errGetProfile, err)
	}

	return r.reconcileSeccompProfile(ctx, seccompProfile, logger)
}

func (r *Reconciler) mergeBaseProfile(
	ctx context.Context, sp *seccompprofileapi.SeccompProfile, l logr.Logger,
) (*seccompprofileapi.SeccompProfile, error) {
	// Recursively resolve the syscalls
	finalSyscalls, err := r.resolveSyscallsForProfile(ctx, sp, sp.Spec.Syscalls, l, 0)
	if err != nil {
		return nil, fmt.Errorf("resolve syscalls: %w", err)
	}

	// Update the final syscalls in the profile for visibility
	scBytes, err := json.Marshal(finalSyscalls)
	if err != nil {
		return nil, fmt.Errorf("marshal syscalls to JSON: %w", err)
	}

	jsonSyscalls := string(scBytes)

	const key = "syscalls"
	if sp.Annotations[key] != jsonSyscalls {
		l.Info("Updating syscall annotations", "profile", sp.Name)

		if sp.Annotations == nil {
			sp.Annotations = make(map[string]string)
		}

		sp.Annotations[key] = jsonSyscalls

		if err := r.client.Update(ctx, sp); err != nil {
			return nil, fmt.Errorf("update seccomp profile annotations: %w", err)
		}
	}

	sp.Spec.Syscalls = finalSyscalls

	return sp, nil
}

// resolveSyscallsForProfile recursively resolves the syscalls for base
// profiles up to a depth level of 15 is also caches the results when pulling
// from OCI artifacts.
func (r *Reconciler) resolveSyscallsForProfile(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	inputSyscalls []*seccompprofileapi.Syscall,
	l logr.Logger,
	level uint8,
) ([]*seccompprofileapi.Syscall, error) {
	const maxLevel = 15
	if level >= maxLevel {
		return nil, fmt.Errorf(
			"max recursion level of %d is reached for resolving base profiles",
			maxLevel,
		)
	}

	baseProfileName := sp.Spec.BaseProfileName
	if baseProfileName == "" {
		// No base profile at all
		return inputSyscalls, nil
	}

	l.Info("Resolving syscalls for profile", "recursion", level)

	var baseProfile *seccompprofileapi.SeccompProfile

	if strings.HasPrefix(baseProfileName, config.OCIProfilePrefix) {
		// Pull remote base profile from an OCI artifact registry
		from := strings.TrimPrefix(baseProfileName, config.OCIProfilePrefix)

		item := r.baseProfiles.Get(from)
		if item != nil {
			l.Info("Using cached base profile", "baseProfile", from)

			baseProfile = item.Value()
		} else {
			spod, err := r.GetSPOD(ctx, r.client)
			if err != nil {
				return nil, fmt.Errorf("retrieving the SPOD configuration: %w", err)
			}

			l.Info(
				"Pulling base profile: "+from,
				"disableOCIArtifactSignatureVerification", spod.Spec.DisableOCIArtifactSignatureVerification,
			)

			res, err := r.Pull(ctx, l, from, "", "", &v1.Platform{
				Architecture: runtime.GOARCH,
				OS:           runtime.GOOS,
			}, spod.Spec.DisableOCIArtifactSignatureVerification)
			if err != nil {
				l.Error(err, "cannot pull base profile "+baseProfileName)
				r.IncSeccompProfileError(r.metrics, reasonCannotPullProfile)
				r.RecordEvent(r.record, sp, util.EventTypeWarning, reasonCannotPullProfile, err.Error())

				return nil, fmt.Errorf("retrieve base profile %s from OCI registry: %w", from, err)
			}

			resType := r.PullResultType(res)
			if resType != artifact.PullResultTypeSeccompProfile {
				return nil, fmt.Errorf("pull result type %s is not a seccomp profile", resType)
			}

			baseProfile = r.PullResultSeccompProfile(res)
			r.baseProfiles.Set(from, baseProfile, ttlcache.DefaultTTL)

			l.Info(
				"Set remote base seccomp profile",
				"baseProfile", baseProfile.Name,
			)
		}
	} else {
		// Local base profile
		profile, err := r.ClientGetProfile(
			ctx, r.client, util.NamespacedName(baseProfileName, sp.GetNamespace()),
		)
		if err != nil {
			l.Error(err, "cannot retrieve base profile "+baseProfileName)
			r.IncSeccompProfileError(r.metrics, reasonInvalidSeccompProfile)
			r.RecordEvent(r.record, sp, util.EventTypeWarning, reasonInvalidSeccompProfile, err.Error())

			return nil, fmt.Errorf("merging base profile: %w", err)
		}

		baseProfile = profile

		l.Info(
			"Set remote base seccomp profile",
			"baseProfile", baseProfile.Name,
			"seccompProfile", sp.Name,
		)
	}

	newSyscalls, err := util.UnionSyscalls(baseProfile.Spec.Syscalls, inputSyscalls)
	if err != nil {
		return nil, fmt.Errorf("union syscalls: %w", err)
	}

	return r.resolveSyscallsForProfile(ctx, baseProfile, newSyscalls, l, level+1)
}

func (r *Reconciler) reconcileSeccompProfile(
	ctx context.Context, sp *seccompprofileapi.SeccompProfile, l logr.Logger,
) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errors.New(errSeccompProfileNil)
	}

	profileName := sp.Name

	nodeStatus, err := nodestatus.NewForProfile(sp, r.client)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus)
	}

	l.Info("Merge possible base profile")

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		l.Error(err, "merge base profile")

		return reconcile.Result{RequeueAfter: wait}, nil
	}

	l.Info("Validate profile")

	if err := r.validateProfile(ctx, outputProfile); err != nil {
		l.Error(err, "validate profile")
		r.metrics.IncSeccompProfileError(reasonProfileNotAllowed)
		r.record.Event(sp, util.EventTypeWarning, reasonProfileNotAllowed, err.Error())

		return reconcile.Result{Requeue: false}, fmt.Errorf("validating profile: %w", err)
	}

	l.Info("Got profile content")

	profileContent, err := json.Marshal(outputProfile.Spec)
	if err != nil {
		l.Error(err, "cannot validate profile "+profileName)
		r.metrics.IncSeccompProfileError(reasonInvalidSeccompProfile)
		r.record.Event(sp, util.EventTypeWarning, reasonInvalidSeccompProfile, err.Error())

		return reconcile.Result{}, fmt.Errorf("cannot validate profile: %w", err)
	}

	profilePath := sp.GetProfilePath()

	// The object is not being deleted
	exists, existErr := nodeStatus.Exists(ctx)
	if existErr != nil {
		return reconcile.Result{}, fmt.Errorf("checking if node status exists: %w", existErr)
	}

	if !exists {
		l.Info("Creating node status")

		if err := nodeStatus.Create(ctx); err != nil {
			return reconcile.Result{}, fmt.Errorf("cannot ensure node status: %w", err)
		}

		l.Info("Created an initial status for this node")

		return reconcile.Result{RequeueAfter: wait}, nil
	}

	if !sp.IsReconcilable() {
		l.Info("Profile is partial or disabled, skipping")

		return reconcile.Result{}, nil
	}

	l.Info("Saving profile to disk")

	updated, err := r.save(profilePath, profileContent)
	if err != nil {
		l.Error(err, "cannot save profile into disk")
		r.metrics.IncSeccompProfileError(reasonCannotSaveProfile)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotSaveProfile, err.Error())

		return reconcile.Result{}, fmt.Errorf("cannot save profile into disk: %w", err)
	}

	if updated {
		evstr := "Successfully saved profile to disk on " + os.Getenv(config.NodeNameEnvKey)
		l.Info(evstr)
		r.metrics.IncSeccompProfileUpdate()
		r.record.Event(sp, util.EventTypeNormal, reasonSavedProfile, evstr)
	}

	l.Info("Checking node status")

	isAlreadyInstalled, getErr := nodeStatus.Matches(ctx, statusv1alpha1.ProfileStateInstalled)
	if getErr != nil {
		l.Error(getErr, "couldn't get current status")

		return reconcile.Result{}, fmt.Errorf("getting status for installed SeccompProfile: %w", getErr)
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")

		return reconcile.Result{}, nil
	}

	l.Info("Set node status to installed")

	if err := nodeStatus.SetNodeStatus(ctx, statusv1alpha1.ProfileStateInstalled); err != nil {
		l.Error(err, "cannot update node status")
		r.metrics.IncSeccompProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateStatus, err.Error())

		return reconcile.Result{}, fmt.Errorf("updating status in SeccompProfile reconciler: %w", err)
	}

	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)

	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	nsc *nodestatus.StatusClient,
) (reconcile.Result, error) {
	hasStatus, err := nsc.Exists(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking if node status exists: %w", err)
	}

	// Set the status if it hasn't been deleted already
	if hasStatus {
		isTerminating, getErr := nsc.Matches(ctx, statusv1alpha1.ProfileStateTerminating)
		if getErr != nil {
			r.log.Error(getErr, "couldn't get current status")

			return reconcile.Result{}, fmt.Errorf("getting status for deleted SeccompProfile: %w", getErr)
		}

		if !isTerminating {
			r.log.Info("setting status to terminating")

			if err := nsc.SetNodeStatus(ctx, statusv1alpha1.ProfileStateTerminating); err != nil {
				r.log.Error(err, "cannot update SeccompProfile status")
				r.metrics.IncSeccompProfileError(reasonCannotUpdateProfile)
				r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateProfile, err.Error())

				return reconcile.Result{}, fmt.Errorf("updating status for deleted SeccompProfile: %w", err)
			}

			return reconcile.Result{Requeue: true, RequeueAfter: wait}, nil
		}
	}

	if controllerutil.ContainsFinalizer(sp, util.HasActivePodsFinalizerString) {
		r.log.Info("cannot delete profile in use by pod, requeuing")

		return reconcile.Result{RequeueAfter: wait}, nil
	}

	if err := r.handleDeletion(sp); err != nil {
		r.log.Error(err, "cannot delete profile")
		r.metrics.IncSeccompProfileError(reasonCannotRemoveProfile)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotRemoveProfile, err.Error())

		return ctrl.Result{}, fmt.Errorf("handling file deletion for deleted SeccompProfile: %w", err)
	}

	if err := nsc.Remove(ctx, r.client); err != nil {
		r.log.Error(err, "cannot remove node status/finalizer from seccomp profile")
		r.metrics.IncSeccompProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateStatus, err.Error())

		return ctrl.Result{}, fmt.Errorf("deleting node status/finalizer for deleted SeccompProfile: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *Reconciler) handleDeletion(sp *seccompprofileapi.SeccompProfile) error {
	profilePath := sp.GetProfilePath()

	err := os.Remove(profilePath)
	if os.IsNotExist(err) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("removing profile from host: %w", err)
	}

	r.log.Info("removed profile " + profilePath)
	r.metrics.IncSeccompProfileDelete()

	return nil
}

func (r *Reconciler) validateProfile(ctx context.Context, profile *seccompprofileapi.SeccompProfile) error {
	spod, err := r.GetSPOD(ctx, r.client)
	if err != nil {
		return fmt.Errorf("retrieving the SPOD configuration: %w", err)
	}

	if len(spod.Spec.AllowedSyscalls) > 0 {
		return allowProfile(profile, spod.Spec.AllowedSyscalls, spod.Spec.AllowedSeccompActions)
	}

	return nil
}

func saveProfileOnDisk(fileName string, content []byte) (updated bool, err error) {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return false, fmt.Errorf("%s: %w", errCreatingOperatorDir, err)
	}

	existingContent, err := os.ReadFile(fileName)
	if err == nil && bytes.Equal(existingContent, content) {
		return false, nil
	}

	if err := os.WriteFile(fileName, content, filePermissionMode); err != nil {
		return false, fmt.Errorf("%s: %w", errSavingProfile, err)
	}

	return true, nil
}

func allowProfile(
	profile *seccompprofileapi.SeccompProfile, allowedSyscalls []string, allowedActions []seccomp.Action,
) error {
	syscalls := map[seccomp.Action]map[string]bool{}
	for _, call := range profile.Spec.Syscalls {
		if _, ok := syscalls[call.Action]; !ok {
			syscalls[call.Action] = map[string]bool{}
		}

		for _, name := range call.Names {
			syscalls[call.Action][name] = true
		}
	}

	allAllowedActions := []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace, seccomp.ActNotify}
	if len(allowedActions) == 0 {
		allowedActions = allAllowedActions
	}

	for _, allowedAction := range allowedActions {
		if !containsAction(allAllowedActions, allowedAction) {
			return fmt.Errorf("%s: %s", errForbiddenAction, allowedAction)
		}
	}

	for _, action := range allowedActions {
		if actionCalls, ok := syscalls[action]; ok {
			for call := range actionCalls {
				if !util.Contains(allowedSyscalls, call) {
					return fmt.Errorf("%s: %s", errForbiddenSyscall, call)
				}
			}
		}

		if profile.Spec.DefaultAction == action && len(allowedSyscalls) > 0 {
			return errors.New(errForbiddenProfile)
		}
	}

	return nil
}

func containsAction(actions []seccomp.Action, action seccomp.Action) bool {
	for _, act := range actions {
		if act == action {
			return true
		}
	}

	return false
}
