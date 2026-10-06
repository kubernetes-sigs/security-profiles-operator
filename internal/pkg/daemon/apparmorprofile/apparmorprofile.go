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
	"sync"
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
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile/crd2armor"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

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

var errAppArmorProfileNil = errors.New("apparmor profile cannot be nil")

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

// A Reconciler reconciles AppArmor profiles.
type Reconciler struct {
	client   client.Client
	log      logr.Logger
	record   util.EventRecorder
	metrics  *metrics.Metrics
	manager  ProfileManager
	nodeName string

	// ptraceWarned holds the profiles which were already reported for using
	// the deprecated ptrace rules in their paths.
	ptraceWarned sync.Map

	// unsupportedCounted holds the UID of every profile, keyed by its name,
	// which was counted in the error metric for a node without AppArmor, so
	// that it is counted once instead of on every reconcile.
	unsupportedCounted sync.Map
}

// countUnsupported reports whether the profile of the name has to be counted
// in the error metric for a node without AppArmor. A profile gets counted once,
// and again if it is deleted and created again.
func (r *Reconciler) countUnsupported(ctx context.Context, name string) bool {
	sp := &apparmorprofileapi.AppArmorProfile{}
	if err := r.client.Get(ctx, client.ObjectKey{Name: name}, sp); err != nil {
		if kerrors.IsNotFound(err) {
			r.unsupportedCounted.Delete(name)
		}

		return false
	}

	previous, counted := r.unsupportedCounted.Swap(name, sp.GetUID())

	return !counted || previous != sp.GetUID()
}

// warnDeprecatedPtraceRules logs once per profile that it puts ptrace rules
// into its filesystem paths, executables or libraries, which is deprecated in
// favour of the ptrace field and will be removed in a future API version.
func (r *Reconciler) warnDeprecatedPtraceRules(
	sp *apparmorprofileapi.AppArmorProfile,
	l logr.Logger,
) {
	if !crd2armor.UsesDeprecatedPtraceRules(&sp.Spec.Abstract) {
		return
	}

	// The UID tells apart a profile which got deleted and created again.
	key := string(sp.GetUID()) + "/" + sp.GetName()
	if _, warned := r.ptraceWarned.LoadOrStore(key, struct{}{}); warned {
		return
	}

	l.Info(crd2armor.DeprecatedPtraceRulesMessage, "profile", sp.GetName())
}

// reportError increments the error metric of the profile for reason and
// records a warning event on it.
func (r *Reconciler) reportError(
	sp *apparmorprofileapi.AppArmorProfile,
	reason, action string,
	err error,
) {
	r.errorReporter(sp).Report(sp, reason, action, err.Error())
}

func (r *Reconciler) errorReporter(sp *apparmorprofileapi.AppArmorProfile) common.ErrorReporter {
	return common.ErrorReporter{
		Record: r.record,
		IncError: func(reason string) {
			r.metrics.IncAppArmorProfileError(sp.GetName(), reason)
		},
	}
}

// deletionReasons returns the event reasons for removing a profile.
func deletionReasons() common.DeletionReasons {
	return common.DeletionReasons{
		CannotUpdateProfile: reasonCannotUpdateProfile,
		CannotRemoveProfile: reasonCannotUnloadProfile,
		CannotUpdateStatus:  common.ReasonCannotUpdateStatus,
	}
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
		return fmt.Errorf("node %q does not support apparmor", r.nodeName)
	}

	return nil
}

// Security Profiles Operator RBAC permissions to manage AppArmorProfile
// The daemon updates the finalizers and labels of the profiles, and the
// profile recorder creates recorded AppArmorProfiles. The profile status is
// written by the manager. The finalizers subresource allows the node statuses
// to block the deletion of their owner profile.
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/finalizers,verbs=get;update;patch

// Reconcile reconciles a AppArmorProfile.
func (r *Reconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name)
	logger.Info("Reconciling AppArmorProfile")

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports AppArmor
	if !r.manager.Enabled() {
		err := errors.New("profile not added")
		logger.Error(
			err,
			fmt.Sprintf("node %q does not support apparmor", r.nodeName),
		)

		if r.record != nil {
			if r.countUnsupported(ctx, req.Name) {
				r.metrics.IncAppArmorProfileError(req.Name, reasonAppArmorNotSupported)
			}

			r.record.Eventf(
				util.EventNode(r.nodeName),
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

		return reconcile.Result{}, fmt.Errorf("%w: %w", common.ErrGetProfile, err)
	}

	return r.reconcileAppArmorProfile(ctx, appArmorProfile, logger)
}

func (r *Reconciler) reconcileAppArmorProfile(
	ctx context.Context, sp *apparmorprofileapi.AppArmorProfile, l logr.Logger,
) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errAppArmorProfileNil
	}

	nodeStatus, err := nodestatus.NewForProfileOnNode(sp, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		return r.reconcileDeletion(ctx, sp, nodeStatus, l)
	}

	// The object is not being deleted. This has to happen before the
	// reconcilable check, so that a partial or disabled profile still reports a
	// node status, exactly like the seccomp and SELinux reconcilers do.
	if res, stop, err := common.EnsureNodeStatusOrRequeue(ctx, nodeStatus, l); stop {
		return res, err
	}

	// A partial profile is still being recorded and a disabled one must not be
	// enforced, so neither may be loaded into the kernel. The seccomp and SELinux
	// reconcilers make the same check.
	if !sp.IsReconcilable() {
		if sp.IsDisabled() && !sp.IsPartial() {
			return r.reconcileDisabled(ctx, sp, nodeStatus, l)
		}

		l.Info("Profile is partial, skipping")

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

	r.warnDeprecatedPtraceRules(sp, l)

	// A failed installation returns an error, so the controller retries it
	// with the exponential backoff of its rate limiter.
	updated, err := r.manager.InstallProfile(sp, isAlreadyInstalled)
	if err != nil {
		l.Error(err, "cannot load profile into node")
		r.reportError(sp, reasonCannotLoadProfile, util.EventActionInstall, err)

		return reconcile.Result{}, fmt.Errorf("cannot load profile into node: %w", err)
	}

	if err := nodeStatus.SetAnnotation(ctx, installedAnnotation, "true"); err != nil {
		l.Error(err, "cannot record profile installation in node status")
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return reconcile.Result{}, fmt.Errorf("recording profile installation: %w", err)
	}

	changed, err := common.MarkInstalled(ctx, sp, nodeStatus, l, r.errorReporter(sp))
	if err != nil {
		return reconcile.Result{}, fmt.Errorf(
			"updating status in AppArmorProfile reconciler: %w", err,
		)
	}

	if !changed {
		return reconcile.Result{}, nil
	}

	l.Info(
		"Reconciled profile from AppArmorProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)

	if updated {
		evstr := "Successfully loaded profile into node " + r.nodeName

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

// reconcileDisabled unloads a disabled profile, which the node may have
// loaded before it got disabled. Unloading a profile unconfines the processes
// which run with it, so a profile in use by pods stays until they are gone.
func (r *Reconciler) reconcileDisabled(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	return common.ReconcileDisabled(
		ctx, sp, nodeStatus, l, r.errorReporter(sp), deletionReasons(),
		// This only removes a profile which this operator installed.
		func() error { return r.handleDeletion(ctx, sp, nodeStatus, l) },
		// The profile is not ours anymore until it gets installed again.
		func() error { return nodeStatus.SetAnnotation(ctx, installedAnnotation, "") },
	)
}

func (r *Reconciler) reconcileDeletion(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nsc *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	return common.ReconcileDeletion(
		ctx,
		sp,
		nsc,
		r.client,
		l,
		r.record,
		deletionReasons(),
		r.errorReporter(sp).IncError,
		func() (reconcile.Result, error) { return reconcile.Result{}, r.handleDeletion(ctx, sp, nsc, l) },
	)
}

func (r *Reconciler) handleDeletion(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) error {
	installed, err := nodeStatus.GetAnnotation(ctx, installedAnnotation)
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("checking if the profile was installed on this node: %w", err)
	}

	if err := r.manager.RemoveProfile(sp, installed == "true"); err != nil {
		return fmt.Errorf("unloading profile from host: %w", err)
	}

	l.Info("removed profile", "profile", sp.GetProfileName())
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
