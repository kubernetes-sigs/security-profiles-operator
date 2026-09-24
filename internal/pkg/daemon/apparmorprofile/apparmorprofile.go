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
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	errAppArmorProfileNil = "apparmor profile cannot be nil"

	reasonAppArmorNotSupported  string = "AppArmorNotSupportedOnNode"
	reasonCannotLoadProfile     string = "CannotLoadAppArmorProfile"
	reasonCannotUnloadProfile   string = "CannotUnloadAppArmorProfile"
	reasonCannotUpdateProfile   string = "CannotUpdateAppArmorProfile"
	reasonLoadedAppArmorProfile string = "LoadedAppArmorProfile"

	// installedAnnotation is set on this node's status once the profile has
	// been loaded here. The status itself moves to terminating before the
	// profile is removed, so the annotation is what still proves on removal
	// that this operator installed the profile on this node.
	installedAnnotation = "spo.x-k8s.io/apparmor-profile-installed"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

// A Reconciler reconciles AppArmor profiles.
type Reconciler struct {
	client  client.Client
	log     logr.Logger
	record  util.EventRecorder
	metrics *metrics.Metrics
	manager ProfileManager
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "apparmor-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() runtime.SchemeBuilder {
	return apparmorprofileapi.SchemeBuilder
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
func (r *Reconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("apparmorprofile", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling AppArmorProfile")

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports AppArmor
	if !r.manager.Enabled() {
		err := errors.New("profile not added")
		logger.Error(
			err,
			fmt.Sprintf("node %q does not support apparmor", os.Getenv(config.NodeNameEnvKey)),
		)

		if r.record != nil {
			r.metrics.IncAppArmorProfileError(req.Name, reasonAppArmorNotSupported)
			r.record.Eventf(
				util.EventNode(os.Getenv(config.NodeNameEnvKey)),
				&apparmorprofileapi.AppArmorProfile{
					ObjectMeta: metav1.ObjectMeta{Name: req.Name},
				},
				util.EventTypeWarning,
				reasonAppArmorNotSupported,
				util.EventActionInstall,
				"node does not support apparmor, %s",
				err.Error(),
			)
		}

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	appArmorProfile := &apparmorprofileapi.AppArmorProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, appArmorProfile); err != nil {
		// Expected to find an AppArmorProfile, return an error and requeue
		if util.IgnoreNotFound(err) == nil {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("%s: %w", common.ErrGetProfile, err)
	}

	return r.reconcileAppArmorProfile(ctx, appArmorProfile, logger)
}

func (r *Reconciler) reconcileAppArmorProfile(
	ctx context.Context, sp *apparmorprofileapi.AppArmorProfile, l logr.Logger,
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

	// The object is not being deleted. This has to happen before the
	// reconcilable check, so that a partial or disabled profile still reports a
	// node status, exactly like the seccomp and SELinux reconcilers do.
	created, result, ensureErr := common.EnsureNodeStatus(ctx, nodeStatus, l)
	if ensureErr != nil {
		return result, ensureErr
	}

	if created {
		return result, nil
	}

	// A partial profile is still being recorded and a disabled one must not be
	// enforced, so neither may be loaded into the kernel. The seccomp and SELinux
	// reconcilers make the same check.
	if !sp.IsReconcilable() {
		l.Info("Profile is partial or disabled, skipping")

		return reconcile.Result{}, nil
	}

	// Read before installing: a profile this node has already installed is ours
	// even if its policy file predates the ownership marker.
	isAlreadyInstalled, getErr := nodeStatus.Matches(
		ctx,
		secprofnodestatusapi.ProfileStateInstalled,
	)
	if getErr != nil {
		l.Error(getErr, "couldn't get current status")

		return reconcile.Result{}, fmt.Errorf(
			"getting status for installed AppArmorProfile: %w",
			getErr,
		)
	}

	// TODO: backoff policy
	updated, err := r.manager.InstallProfile(sp, isAlreadyInstalled)
	if err != nil {
		l.Error(err, "cannot load profile into node")
		r.metrics.IncAppArmorProfileError(sp.GetName(), reasonCannotLoadProfile)
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			reasonCannotLoadProfile,
			util.EventActionInstall,
			"%s",
			err.Error(),
		)

		return reconcile.Result{}, fmt.Errorf("cannot load profile into node: %w", err)
	}

	if err := nodeStatus.SetAnnotation(ctx, installedAnnotation, "true"); err != nil {
		l.Error(err, "cannot record profile installation in node status")
		r.metrics.IncAppArmorProfileError(sp.GetName(), common.ReasonCannotUpdateStatus)
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			common.ReasonCannotUpdateStatus,
			util.EventActionUpdate,
			"%s",
			err.Error(),
		)

		return reconcile.Result{}, fmt.Errorf("recording profile installation: %w", err)
	}

	if isAlreadyInstalled {
		l.Info("Already in the expected Installed state")

		return reconcile.Result{}, nil
	}

	if err := nodeStatus.SetNodeStatus(
		ctx,
		secprofnodestatusapi.ProfileStateInstalled,
	); err != nil {
		l.Error(err, "cannot update node status")
		r.metrics.IncAppArmorProfileError(sp.GetName(), common.ReasonCannotUpdateStatus)
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			common.ReasonCannotUpdateStatus,
			util.EventActionUpdate,
			"%s",
			err.Error(),
		)

		return reconcile.Result{}, fmt.Errorf(
			"updating status in AppArmorProfile reconciler: %w",
			err,
		)
	}

	l.Info(
		"Reconciled profile from AppArmorProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)

	if updated {
		evstr := "Successfully loaded profile into node " + os.Getenv(config.NodeNameEnvKey)

		r.metrics.IncAppArmorProfileUpdate()
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeNormal,
			reasonLoadedAppArmorProfile,
			util.EventActionInstall,
			"%s",
			evstr,
		)
	}

	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nsc *nodestatus.StatusClient,
) (reconcile.Result, error) {
	return common.ReconcileDeletion(
		ctx, sp, nsc, r.client, r.log, r.record,
		common.DeletionReasons{
			CannotUpdateProfile: reasonCannotUpdateProfile,
			CannotRemoveProfile: reasonCannotUnloadProfile,
			CannotUpdateStatus:  common.ReasonCannotUpdateStatus,
		},
		func(reason string) { r.metrics.IncAppArmorProfileError(sp.GetName(), reason) },
		func() error { return r.handleDeletion(ctx, sp, nsc) },
	)
}

func (r *Reconciler) handleDeletion(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
) error {
	installed, err := nodeStatus.GetAnnotation(ctx, installedAnnotation)
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("checking if the profile was installed on this node: %w", err)
	}

	if err := r.manager.RemoveProfile(sp, installed == "true"); err != nil {
		return fmt.Errorf("unloading profile from host: %w", err)
	}

	r.log.Info("removed profile", "profile", sp.GetProfileName())
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
		r.log.Info("apparmor enabled", "status", ok(enabled, err))

		enforceable, err := a.Enforceable()
		r.log.Info("apparmor enforceable", "status", ok(enforceable, err))

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
