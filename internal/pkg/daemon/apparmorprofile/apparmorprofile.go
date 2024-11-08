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
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	aa "github.com/pjbgf/go-apparmor/pkg/apparmor"
	"github.com/pjbgf/go-apparmor/pkg/hostop"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
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

	reasonAppArmorNotSupported  string = "AppArmorNotSupportedOnNode"
	reasonCannotUpdateStatus    string = "CannotUpdateNodeStatus"
	reasonCannotLoadProfile     string = "CannotLoadAppArmorProfile"
	reasonCannotUnloadProfile   string = "CannotUnloadAppArmorProfile"
	reasonCannotUpdateProfile   string = "CannotUpdateAppArmorProfile"
	reasonLoadedAppArmorProfile string = "LoadedAppArmorProfile"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

// A Reconciler reconciles AppArmor profiles.
type Reconciler struct {
	client  client.Client
	log     logr.Logger
	record  record.EventRecorder
	metrics *metrics.Metrics
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
	return r.checkAppArmor()
}

func (r *Reconciler) checkAppArmor() error {
	if !r.manager.Enabled() {
		return fmt.Errorf("node %q does not support apparmor", os.Getenv(config.NodeNameEnvKey))
	}
	return nil
}

// Security Profiles Operator RBAC permissions to manage AppArmorProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/finalizers,verbs=delete;get;update;patch

// Reconcile reconciles a AppArmorProfile.
func (r *Reconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("apparmorprofile", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling AppArmorProfile")

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports AppArmor
	if !r.manager.Enabled() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support apparmor", os.Getenv(config.NodeNameEnvKey)))
		if r.record != nil {
			r.metrics.IncAppArmorProfileError(reasonAppArmorNotSupported)
			r.record.AnnotatedEventf(
				&v1alpha1.AppArmorProfile{},
				map[string]string{os.Getenv(config.NodeNameEnvKey): "node does not support apparmor"},
				util.EventTypeWarning,
				reasonAppArmorNotSupported,
				err.Error(),
			)
		}

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	appArmorProfile := &v1alpha1.AppArmorProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, appArmorProfile); err != nil {
		// Expected to find an AppArmorProfile, return an error and requeue
		if util.IgnoreNotFound(err) == nil {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("%s: %w", errGetProfile, err)
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
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus)
	}

	// The object is not being deleted
	exists, existErr := nodeStatus.Exists(ctx)
	if existErr != nil {
		return reconcile.Result{}, fmt.Errorf("checking if node status exists: %w", existErr)
	}

	if !exists {
		if err := nodeStatus.Create(ctx); err != nil {
			return reconcile.Result{}, fmt.Errorf("cannot ensure node status: %w", err)
		}
		l.Info("Created an initial status for this node")
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	// TODO: backoff policy
	updated, err := r.manager.InstallProfile(sp)
	if err != nil {
		l.Error(err, "cannot load profile into node")
		r.metrics.IncAppArmorProfileError(reasonCannotLoadProfile)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotLoadProfile, err.Error())
		return reconcile.Result{}, fmt.Errorf("cannot load profile into node: %w", err)
	}

	isAlreadyInstalled, getErr := nodeStatus.Matches(ctx, statusv1alpha1.ProfileStateInstalled)
	if getErr != nil {
		l.Error(getErr, "couldn't get current status")
		return reconcile.Result{}, fmt.Errorf("getting status for installed AppArmorProfile: %w", getErr)
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")
		return reconcile.Result{}, nil
	}

	if err := nodeStatus.SetNodeStatus(ctx, statusv1alpha1.ProfileStateInstalled); err != nil {
		l.Error(err, "cannot update node status")
		r.metrics.IncAppArmorProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateStatus, err.Error())
		return reconcile.Result{}, fmt.Errorf("updating status in AppArmorProfile reconciler: %w", err)
	}

	l.Info(
		"Reconciled profile from AppArmorProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	if updated {
		evstr := "Successfully loaded profile into node " + os.Getenv(config.NodeNameEnvKey)
		r.metrics.IncAppArmorProfileUpdate()
		r.record.Event(sp, util.EventTypeNormal, reasonLoadedAppArmorProfile, evstr)
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
		return ctrl.Result{}, fmt.Errorf("checking if node status exists: %w", err)
	}

	// Set the status if it hasn't been deleted already
	if hasStatus {
		isTerminating, getErr := nsc.Matches(ctx, statusv1alpha1.ProfileStateTerminating)
		if getErr != nil {
			r.log.Error(getErr, "couldn't get current status")
			return reconcile.Result{}, fmt.Errorf("getting status for deleted AppArmorProfile: %w", getErr)
		}

		if !isTerminating {
			r.log.Info("setting status to terminating")
			if err := nsc.SetNodeStatus(ctx, statusv1alpha1.ProfileStateTerminating); err != nil {
				r.log.Error(err, "cannot update AppArmorProfile status")
				r.metrics.IncAppArmorProfileError(reasonCannotUpdateProfile)
				r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateProfile, err.Error())
				return reconcile.Result{}, fmt.Errorf("updating status for deleted AppArmorProfile: %w", err)
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
		r.record.Event(sp, util.EventTypeWarning, reasonCannotUnloadProfile, err.Error())
		return ctrl.Result{}, fmt.Errorf("handling file deletion for deleted AppArmorProfile: %w", err)
	}

	if err := nsc.Remove(ctx, r.client); err != nil {
		r.log.Error(err, "cannot remove node status/finalizer from apparmor profile")
		r.metrics.IncAppArmorProfileError(reasonCannotUpdateStatus)
		r.record.Event(sp, util.EventTypeWarning, reasonCannotUpdateStatus, err.Error())
		return ctrl.Result{}, fmt.Errorf("deleting node status/finalizer for deleted AppArmorProfile: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) handleDeletion(sp *v1alpha1.AppArmorProfile) error {
	if err := r.manager.RemoveProfile(sp); err != nil {
		return fmt.Errorf("unloading profile from host: %w", err)
	}
	r.log.Info("removed profile " + sp.GetProfileName())
	r.metrics.IncAppArmorProfileDelete()
	return nil
}

func (r *Reconciler) logNodeInfo() {
	r.log.Info("detecting apparmor support...")

	mount := hostop.NewMountHostOp(
		hostop.WithLogger(r.log),
		hostop.WithAssumeContainer(),
		hostop.WithAssumeHostPidNamespace())
	a := aa.NewAppArmor(aa.WithLogger(r.log))

	err := mount.Do(func() error {
		enabled, err := a.Enabled()
		r.log.Info("apparmor enabled: " + ok(enabled, err))

		enforceable, err := a.Enforceable()
		r.log.Info("apparmor enforceable: " + ok(enforceable, err))

		return nil
	})
	if err != nil {
		r.log.Error(err, "mounting host")
	}
}

func ok(ok bool, err error) string {
	if ok {
		return "OK"
	}
	return fmt.Sprintf("NOT OK (%v)", err)
}
