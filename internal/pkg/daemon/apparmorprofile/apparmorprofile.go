/*
Copyright 2021 The Kubernetes Authors.

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

package apparmorprofile

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
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

	errGetProfile         = "cannot get profile"
	errAppArmorProfileNil = "apparmor profile cannot be nil"

	reasonAppArmorNotSupported event.Reason = "AppArmorNotSupportedOnNode"
	reasonCannotUpdateStatus   event.Reason = "CannotUpdateNodeStatus"
	reasonCannotLoadProfile    event.Reason = "CannotLoadAppArmorProfile"
	reasonCannotUnloadProfile  event.Reason = "CannotUnloadAppArmorProfile"
	reasonCannotUpdateProfile  event.Reason = "CannotUpdateAppArmorProfile"

	reasonLoadedAppArmorProfile event.Reason = "LoadedAppArmorProfile"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

// A Reconciler reconciles AppArmor profiles.
type Reconciler struct {
	client  client.Client
	log     logr.Logger
	record  event.Recorder
	metrics *metrics.Metrics
	ready   atomic.Bool
	manager ProfileManager
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "apparmor-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() *scheme.Builder {
	return v1alpha1.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *Reconciler) Healthz(*http.Request) error {
	if !r.ready.Get() {
		return errors.New("not ready")
	}
	return nil
}

// Security Profiles Operator RBAC permissions to manage AppArmorProfile
// nolint:lll
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch

// OpenShift ... This is ignored in other distros
// nolint:lll
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resources=securitycontextconstraints,verbs=use

// Reconcile reconciles a AppArmorProfile.
func (r *Reconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	// Mark the controller as ready if the first reconcile has been finished
	if !r.ready.Get() {
		defer func() { r.ready.Set(true) }()
	}

	logger := r.log.WithValues("apparmorprofile", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling AppArmorProfile")

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports AppArmor
	if !r.manager.Enabled() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support apparmor", os.Getenv(config.NodeNameEnvKey)))
		if r.record != nil {
			r.metrics.IncAppArmorProfileError(reasonAppArmorNotSupported)
			r.record.Event(&v1alpha1.AppArmorProfile{},
				event.Warning(reasonAppArmorNotSupported, err, os.Getenv(config.NodeNameEnvKey),
					"node does not support apparmor"))
		}

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	appArmorProfile := &v1alpha1.AppArmorProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, appArmorProfile); err != nil {
		// Expected to find an AppArmorProfile, return an error and requeue
		return reconcile.Result{}, errors.Wrap(util.IgnoreNotFound(err), errGetProfile)
	}

	return r.reconcileAppArmorProfile(ctx, appArmorProfile, logger)
}

func (r *Reconciler) reconcileAppArmorProfile(
	ctx context.Context, sp *v1alpha1.AppArmorProfile, l logr.Logger,
) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errors.New(errAppArmorProfileNil)
	}

	nodeStatus, err := nodestatus.NewForProfile(sp, r.client)
	if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "cannot create nodeStatus")
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus)
	}

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

	// TODO: backoff policy
	updated, err := r.manager.InstallProfile(sp)
	if err != nil {
		l.Error(err, "cannot load profile into node")
		r.metrics.IncAppArmorProfileError(reasonCannotLoadProfile)
		r.record.Event(sp, event.Warning(reasonCannotLoadProfile, err))
		return reconcile.Result{}, errors.Wrap(err, "cannot load profile into node")
	}

	isAlreadyInstalled, getErr := nodeStatus.Matches(ctx, statusv1alpha1.ProfileStateInstalled)
	if getErr != nil {
		l.Error(err, "couldn't get current status")
		return reconcile.Result{}, errors.Wrap(err, "getting status for installed AppArmorProfile")
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")
		return reconcile.Result{}, nil
	}

	if err := nodeStatus.SetNodeStatus(ctx, statusv1alpha1.ProfileStateInstalled); err != nil {
		l.Error(err, "cannot update node status")
		r.metrics.IncAppArmorProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, event.Warning(reasonCannotUpdateStatus, err))
		return reconcile.Result{}, errors.Wrap(err, "updating status in AppArmorProfile reconciler")
	}

	l.Info(
		"Reconciled profile from AppArmorProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	if updated {
		evstr := fmt.Sprintf("Successfully loaded profile into node %s", os.Getenv(config.NodeNameEnvKey))
		r.metrics.IncAppArmorProfileUpdate()
		r.record.Event(sp, event.Normal(reasonLoadedAppArmorProfile, evstr))
	}
	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *v1alpha1.AppArmorProfile,
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
			return reconcile.Result{}, errors.Wrap(err, "getting status for deleted AppArmorProfile")
		}

		if !isTerminating {
			r.log.Info("setting status to terminating")
			if err := nsc.SetNodeStatus(ctx, statusv1alpha1.ProfileStateTerminating); err != nil {
				r.log.Error(err, "cannot update AppArmorProfile status")
				r.metrics.IncAppArmorProfileError(reasonCannotUpdateProfile)
				r.record.Event(sp, event.Warning(reasonCannotUpdateProfile, err))
				return reconcile.Result{}, errors.Wrap(err, "updating status for deleted AppArmorProfile")
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
		r.metrics.IncAppArmorProfileError(reasonCannotUnloadProfile)
		r.record.Event(sp, event.Warning(reasonCannotUnloadProfile, err))
		return ctrl.Result{}, errors.Wrap(err, "handling file deletion for deleted AppArmorProfile")
	}

	if err := nsc.Remove(ctx, r.client); err != nil {
		r.log.Error(err, "cannot remove node status/finalizer from apparmor profile")
		r.metrics.IncAppArmorProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, event.Warning(reasonCannotUpdateStatus, err))
		return ctrl.Result{}, errors.Wrap(err, "deleting node status/finalizer for deleted AppArmorProfile")
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) handleDeletion(sp *v1alpha1.AppArmorProfile) error {
	err := r.manager.RemoveProfile(sp)
	if err != nil {
		return errors.Wrap(err, "unloading profile from host")
	}
	r.log.Info(fmt.Sprintf("removed profile %s", sp.GetProfileName()))
	r.metrics.IncAppArmorProfileDelete()
	return nil
}
