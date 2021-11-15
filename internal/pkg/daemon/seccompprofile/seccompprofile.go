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
	"net/http"
	"os"
	"path"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/atomic"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	wait = 10 * time.Second

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
	reasonCannotSaveProfile     event.Reason = "CannotSaveSeccompProfile"
	reasonCannotRemoveProfile   event.Reason = "CannotRemoveSeccompProfile"
	reasonCannotUpdateProfile   event.Reason = "CannotUpdateSeccompProfile"
	reasonCannotUpdateStatus    event.Reason = "CannotUpdateNodeStatus"

	reasonSavedProfile event.Reason = "SavedSeccompProfile"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

type saver func(string, []byte) (bool, error)

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client  client.Client
	log     logr.Logger
	record  event.Recorder
	save    saver
	metrics *metrics.Metrics
	ready   atomic.Bool
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "seccomp-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() *scheme.Builder {
	return v1alpha1.SchemeBuilder
}

// Setup adds a controller that reconciles seccomp profiles.
func (r *Reconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = event.NewAPIRecorder(mgr.GetEventRecorderFor("profile"))
	r.save = saveProfileOnDisk
	r.metrics = met

	// Register the regular reconciler to manage SeccompProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&v1alpha1.SeccompProfile{}).
		Complete(r)
}

// Healthz is the liveness probe endpoint of the controller.
func (r *Reconciler) Healthz(*http.Request) error {
	if !r.ready.Get() {
		return errors.New("not ready")
	}
	return nil
}

// Security Profiles Operator RBAC permissions to manage SeccompProfile
// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch

// OpenShift ... This is ignored in other distros
// nolint:lll
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resources=securitycontextconstraints,verbs=use

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	// Mark the controller as ready if the first reconcile has been finished
	if !r.ready.Get() {
		defer func() { r.ready.Set(true) }()
	}

	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		if r.record != nil {
			r.metrics.IncSeccompProfileError(reasonSeccompNotSupported)
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
		return reconcile.Result{}, errors.Wrap(util.IgnoreNotFound(err), errGetProfile)
	}

	return r.reconcileSeccompProfile(ctx, seccompProfile, logger)
}

// OutputProfile represents the on-disk form of the SeccompProfile.
type OutputProfile struct {
	DefaultAction seccomp.Action      `json:"defaultAction"`
	Architectures []v1alpha1.Arch     `json:"architectures,omitempty"`
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
		r.metrics.IncSeccompProfileError(reasonInvalidSeccompProfile)
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

	nodeStatus, err := nodestatus.NewForProfile(sp, r.client)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus")
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus)
	}

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	profileContent, err := json.Marshal(outputProfile)
	if err != nil {
		l.Error(err, "cannot validate profile "+profileName)
		r.metrics.IncSeccompProfileError(reasonInvalidSeccompProfile)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "cannot validate profile")
	}

	profilePath := sp.GetProfilePath()

	// The object is not being deleted
	exists, existErr := nodeStatus.Exists(ctx)

	if existErr != nil {
		return reconcile.Result{}, errors.Wrap(existErr, "checking if node status exists")
	}

	if !exists {
		if err := nodeStatus.Create(ctx); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "cannot ensure node status")
		}
		l.Info("Created an initial status for this node")
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	updated, err := r.save(profilePath, profileContent)
	if err != nil {
		l.Error(err, "cannot save profile into disk")
		r.metrics.IncSeccompProfileError(reasonCannotSaveProfile)
		r.record.Event(sp, event.Warning(reasonCannotSaveProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "cannot save profile into disk")
	}

	isAlreadyInstalled, getErr := nodeStatus.Matches(ctx, statusv1alpha1.ProfileStateInstalled)
	if getErr != nil {
		l.Error(err, "couldn't get current status")
		return reconcile.Result{}, errors.Wrap(err, "getting status for installed SeccompProfile")
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")
		return reconcile.Result{}, nil
	}

	if err := nodeStatus.SetNodeStatus(ctx, statusv1alpha1.ProfileStateInstalled); err != nil {
		l.Error(err, "cannot update node status")
		r.metrics.IncSeccompProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, event.Warning(reasonCannotUpdateStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "updating status in SeccompProfile reconciler")
	}

	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	if updated {
		evstr := fmt.Sprintf("Successfully saved profile to disk on %s", os.Getenv(config.NodeNameEnvKey))
		r.metrics.IncSeccompProfileUpdate()
		r.record.Event(sp, event.Normal(reasonSavedProfile, evstr))
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *v1alpha1.SeccompProfile,
	nsc *nodestatus.StatusClient,
) (reconcile.Result, error) {
	hasStatus, err := nsc.Exists(ctx)
	if err != nil {
		return ctrl.Result{}, errors.Wrap(err, "checking if node status exists")
	}

	// Set the status if it hasn't been deleted already
	if hasStatus {
		isTerminating, getErr := nsc.Matches(ctx, statusv1alpha1.ProfileStateTerminating)
		if getErr != nil {
			r.log.Error(err, "couldn't get current status")
			return reconcile.Result{}, errors.Wrap(err, "getting status for deleted SeccompProfile")
		}

		if !isTerminating {
			r.log.Info("setting status to terminating")
			if err := nsc.SetNodeStatus(ctx, statusv1alpha1.ProfileStateTerminating); err != nil {
				r.log.Error(err, "cannot update SeccompProfile status")
				r.metrics.IncSeccompProfileError(reasonCannotUpdateProfile)
				r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
				return reconcile.Result{}, errors.Wrap(err, "updating status for deleted SeccompProfile")
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
		r.record.Event(sp, event.Warning(reasonCannotRemoveProfile, err))
		return ctrl.Result{}, errors.Wrap(err, "handling file deletion for deleted SeccompProfile")
	}

	if err := nsc.Remove(ctx, r.client); err != nil {
		r.log.Error(err, "cannot remove node status/finalizer from seccomp profile")
		r.metrics.IncSeccompProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, event.Warning(reasonCannotUpdateStatus, err))
		return ctrl.Result{}, errors.Wrap(err, "deleting node status/finalizer for deleted SeccompProfile")
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) handleDeletion(sp *v1alpha1.SeccompProfile) error {
	profilePath := sp.GetProfilePath()
	err := os.Remove(profilePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.Wrap(err, "removing profile from host")
	}
	r.log.Info(fmt.Sprintf("removed profile %s", profilePath))
	r.metrics.IncSeccompProfileDelete()
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
