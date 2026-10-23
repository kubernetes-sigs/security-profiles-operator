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
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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

	// rejectedRetry is how often a profile which conflicts with one of the
	// host is checked again, because the host may remove its profile.
	rejectedRetry = 5 * time.Minute

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

// errNodeWithoutAppArmor is reported for the profiles of a node without
// AppArmor.
var errNodeWithoutAppArmor = errors.New("node does not support apparmor, profile not added")

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &Reconciler{}
}

// A Reconciler reconciles AppArmor profiles.
type Reconciler struct {
	client   client.Client
	reader   client.Reader
	log      logr.Logger
	record   util.EventRecorder
	metrics  *metrics.Metrics
	manager  ProfileManager
	nodeName string

	// ptraceWarned holds the UID of the profiles which were already reported
	// for using the deprecated ptrace rules in their paths.
	ptraceWarned common.Reports[types.UID]

	// traversalWarned holds the generation of the profiles which were
	// already reported for file system paths with a directory traversal.
	traversalWarned common.Reports[int64]

	// unsupported remembers the profiles which got reported for a node
	// without AppArmor.
	unsupported common.UnsupportedReports

	// rejected holds the reported rejection of the profiles which cannot be
	// loaded, like the ones which conflict with a profile of the host or of
	// a container runtime.
	rejected common.Reports[rejection]

	// writtenStates keeps the node status states this node wrote.
	writtenStates nodestatus.WrittenStates
}

// rejection is a conflict of a profile which got reported.
type rejection struct {
	uid types.UID
	msg string
}

// forgetProfile forgets what got reported about a profile which is gone or
// being deleted, so that the same name gets reported again once created
// again.
func (r *Reconciler) forgetProfile(key types.NamespacedName) {
	r.ptraceWarned.Forget(key)
	r.traversalWarned.Forget(key)
	r.rejected.Forget(key)
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
	if !r.ptraceWarned.ShouldReport(client.ObjectKeyFromObject(sp), sp.GetUID()) {
		return
	}

	l.Info(crd2armor.DeprecatedPtraceRulesMessage, "profile", sp.GetName())
}

// warnTraversalPaths logs once per profile generation the file system paths
// with a directory traversal. They stay in the policy like before, the rest
// of the profile is enforced, but their rules never match anything.
func (r *Reconciler) warnTraversalPaths(
	sp *apparmorprofileapi.AppArmorProfile,
	l logr.Logger,
) {
	paths := crd2armor.TraversalPaths(&sp.Spec.Abstract)
	if len(paths) == 0 {
		return
	}

	if !r.traversalWarned.ShouldReport(client.ObjectKeyFromObject(sp), sp.GetGeneration()) {
		return
	}

	l.Info("WARNING: "+crd2armor.TraversalPathsMessage, "profile", sp.GetName(), "paths", paths)
}

// reportError increments the error metric of the profile for reason and
// records a warning event on it.
func (r *Reconciler) reportError(
	sp *apparmorprofileapi.AppArmorProfile,
	reason, action string,
	err error,
) {
	r.errorReporter(sp.GetName()).ReportError(sp, reason, action, err)
}

// errorReporter returns the reporter of the errors of the profile with the
// name, whose error metric is labeled with it.
func (r *Reconciler) errorReporter(name string) common.ErrorReporter {
	return common.ErrorReporter{
		Record: r.record,
		IncError: func(reason string) {
			r.metrics.IncAppArmorProfileError(name, reason)
		},
	}
}

// deletionReasons returns the event reasons for removing a profile.
func deletionReasons() common.DeletionReasons {
	return common.NewDeletionReasons(reasonCannotUpdateProfile, reasonCannotUnloadProfile)
}

// Name returns the name of the controller.
func (r *Reconciler) Name() string {
	return "apparmor-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *Reconciler) SchemeBuilder() runtime.SchemeBuilder {
	return apparmorprofileapi.SchemeBuilder
}

// Security Profiles Operator RBAC permissions to manage AppArmorProfile
// The daemon updates the finalizers and labels of the profiles, and the
// profile recorder creates recorded AppArmorProfiles. The profile status is
// written by the manager. The finalizers subresource allows the node statuses
// to block the deletion of their owner profile.
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/finalizers,verbs=get;update;patch

// Reconcile reconciles a AppArmorProfile.
func (r *Reconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name)
	logger.V(config.VerboseLevel).Info("Reconciling AppArmorProfile")

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if !r.manager.Enabled() {
		// Every profile is counted in the error metric and gets a warning
		// event once, and again if it is created again, instead of on
		// every reconcile. The error series of a profile which is gone get
		// dropped, like on a node with AppArmor.
		profile := &apparmorprofileapi.AppArmorProfile{}
		if r.unsupported.Report(
			ctx, r.client, req.NamespacedName, profile, logger,
			r.errorReporter(req.Name), r.nodeName, reasonAppArmorNotSupported,
			errNodeWithoutAppArmor,
		) {
			r.metrics.DeleteAppArmorProfileErrors(req.Name)

			return reconcile.Result{}, nil
		}

		// A failed detection tells nothing about the profiles installed on
		// the node, they keep their finalizer then.
		if !r.manager.KnownUnsupported() {
			return reconcile.Result{}, nil
		}

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, common.ReleaseUnsupported(
			ctx, r.client, r.reader, profile, r.nodeName, &r.writtenStates,
		)
	}

	appArmorProfile := &apparmorprofileapi.AppArmorProfile{}
	if found, err := common.GetProfile(ctx, r.client, req.NamespacedName, appArmorProfile); !found {
		if err == nil {
			r.forgetProfile(req.NamespacedName)
			r.writtenStates.Forget(req.NamespacedName)
			// The error series of a profile which is gone would stay
			// around for the lifetime of the daemon otherwise.
			r.metrics.DeleteAppArmorProfileErrors(req.Name)
		}

		return reconcile.Result{}, err
	}

	return r.reconcileAppArmorProfile(ctx, appArmorProfile, logger)
}

func (r *Reconciler) reconcileAppArmorProfile(
	ctx context.Context, sp *apparmorprofileapi.AppArmorProfile, l logr.Logger,
) (reconcile.Result, error) {
	nodeStatus, err := nodestatus.NewForProfileOnNode(sp, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	nodeStatus.WithAPIReader(r.reader)
	nodeStatus.WithWrittenStates(&r.writtenStates)

	if !sp.GetDeletionTimestamp().IsZero() { // object is being deleted
		r.forgetProfile(client.ObjectKeyFromObject(sp))

		return r.reconcileDeletion(ctx, sp, nodeStatus, l)
	}

	// The object is not being deleted. This has to happen before the
	// reconcilable check, so that a partial or disabled profile still reports a
	// node status, exactly like the seccomp and SELinux reconcilers do. A
	// status which just got created is updated in the same reconcile.
	if _, _, err := common.EnsureNodeStatus(ctx, nodeStatus, l); err != nil {
		return reconcile.Result{}, err
	}

	// A partial profile is still being recorded and a disabled one must not be
	// enforced, so neither may be loaded into the kernel. The seccomp and SELinux
	// reconcilers make the same check.
	if !sp.IsReconcilable() {
		if sp.IsDisabled() && !sp.IsPartial() {
			return r.reconcileDisabled(ctx, sp, nodeStatus, l)
		}

		l.V(config.VerboseLevel).Info("Profile is partial, skipping")

		return reconcile.Result{}, nil
	}

	if err := r.installProfile(ctx, sp, nodeStatus, l); err != nil {
		if isRejection(err) {
			return r.rejectProfile(ctx, sp, nodeStatus, err, l)
		}

		return reconcile.Result{}, err
	}

	r.rejected.Forget(client.ObjectKeyFromObject(sp))

	return reconcile.Result{}, r.markInstalled(ctx, sp, nodeStatus, l)
}

// isRejection reports whether a profile cannot be loaded until it or the host
// changes, see rejectProfile.
func isRejection(err error) bool {
	return errors.Is(err, ErrProfileExists) ||
		errors.Is(err, ErrHostPolicyFile) ||
		errors.Is(err, ErrRuntimeProfile) ||
		errors.Is(err, ErrOperatorProfile) ||
		errors.Is(err, ErrInvalidProfile)
}

// rejectProfile sets the node status of a profile which cannot be loaded to
// error: it conflicts with a profile of the host, of a container runtime or
// of the operator, or its policy cannot be generated. Retrying it with the
// backoff of the rate limiter would only repeat the same warning.
func (r *Reconciler) rejectProfile(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	rejectErr error,
	l logr.Logger,
) (reconcile.Result, error) {
	// The conflict is reported once, also if the profile failed for another
	// reason before.
	report := rejection{uid: sp.GetUID(), msg: rejectErr.Error()}

	if r.rejected.ShouldReport(client.ObjectKeyFromObject(sp), report) {
		l.Error(rejectErr, "Not installing profile")
		r.reportError(sp, reasonCannotLoadProfile, util.EventActionInstall, rejectErr)
	}

	if err := nodeStatus.SetNodeStatusWithMessage(
		ctx,
		secprofnodestatusapi.ProfileStateError,
		rejectErr.Error(),
	); err != nil {
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return reconcile.Result{}, fmt.Errorf("setting node status to error: %w", err)
	}

	// Only the host can resolve a conflict with one of its profiles or
	// policy files without a change of the profile, which reconciles it
	// anyway. A reserved name or an invalid policy stays rejected until
	// then.
	if errors.Is(rejectErr, ErrProfileExists) || errors.Is(rejectErr, ErrHostPolicyFile) {
		return reconcile.Result{RequeueAfter: rejectedRetry}, nil
	}

	return reconcile.Result{}, nil
}

// installProfile loads the profile into the kernel and records on the node
// status that this node installed it. A failed installation sets the node
// status to error and returns an error, so the controller retries it with the
// exponential backoff of its rate limiter.
func (r *Reconciler) installProfile(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) error {
	// Read before installing: a profile this node has already installed is ours
	// even if its policy file predates the ownership marker.
	isAlreadyInstalled, err := nodeStatus.Matches(
		ctx,
		secprofnodestatusapi.ProfileStateInstalled,
	)
	if err != nil {
		l.Error(err, "couldn't get current status")

		return fmt.Errorf("getting status for installed AppArmorProfile: %w", err)
	}

	// A failed installation sets the status to error, the annotation tells
	// the installation then.
	ownedByUs := isAlreadyInstalled
	if !ownedByUs {
		installed, err := nodeStatus.GetAnnotation(ctx, installedAnnotation)
		if err != nil {
			return fmt.Errorf("checking if the profile was installed on this node: %w", err)
		}

		ownedByUs = installed == "true"
	}

	r.warnDeprecatedPtraceRules(sp, l)
	r.warnTraversalPaths(sp, l)

	// The profiles of the operator carry the ownership marker, so only the
	// name tells that they are not the ones of this profile.
	if isOperatorProfile(sp.GetProfileName()) {
		return fmt.Errorf("cannot load profile into node: %w", ErrOperatorProfile)
	}

	updated, err := r.manager.InstallProfile(sp, ownedByUs)
	if isRejection(err) {
		// Reported by rejectProfile.
		return fmt.Errorf("cannot load profile into node: %w", err)
	}

	if err != nil {
		l.Error(err, "cannot load profile into node")
		r.reportError(sp, reasonCannotLoadProfile, util.EventActionInstall, err)

		return r.failInstallation(ctx, sp, nodeStatus, isAlreadyInstalled, err)
	}

	// A profile which is installed already gets loaded again when its policy
	// changed, which does not change its node status, so this is reported
	// independent of it.
	if updated {
		r.reportLoaded(sp)
	}

	if err := nodeStatus.SetAnnotation(ctx, installedAnnotation, "true"); err != nil {
		l.Error(err, "cannot record profile installation in node status")
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return fmt.Errorf("recording profile installation: %w", err)
	}

	return nil
}

// failInstallation sets the node status of a profile which failed to load to
// error. The previous policy of a profile which is installed already stays
// loaded. Its installation gets recorded first, a status of an earlier release
// only tells it by its state, which the error replaces.
func (r *Reconciler) failInstallation(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	recordInstalled bool,
	installErr error,
) error {
	if recordInstalled {
		if err := nodeStatus.SetAnnotation(ctx, installedAnnotation, "true"); err != nil {
			r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

			return fmt.Errorf("recording profile installation: %w", err)
		}
	}

	if err := nodeStatus.SetNodeStatusWithMessage(
		ctx,
		secprofnodestatusapi.ProfileStateError,
		installErr.Error(),
	); err != nil {
		r.reportError(sp, common.ReasonCannotUpdateStatus, util.EventActionUpdate, err)

		return fmt.Errorf("setting node status to error: %w", err)
	}

	return fmt.Errorf("cannot load profile into node: %w", installErr)
}

// reportLoaded counts a loaded policy in the update metric and records an
// event on the profile.
func (r *Reconciler) reportLoaded(sp *apparmorprofileapi.AppArmorProfile) {
	r.metrics.IncAppArmorProfileUpdate()
	r.record.Eventf(
		sp,
		nil,
		corev1.EventTypeNormal,
		reasonLoadedAppArmorProfile,
		util.EventActionInstall,
		"%s",
		"Successfully loaded profile into node "+r.nodeName,
	)
}

// markInstalled sets the node status of the loaded profile to installed.
func (r *Reconciler) markInstalled(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) error {
	changed, err := common.MarkInstalled(ctx, sp, nodeStatus, l, r.errorReporter(sp.GetName()))
	if err != nil {
		return fmt.Errorf("updating status in AppArmorProfile reconciler: %w", err)
	}

	if changed {
		l.Info(
			"Reconciled profile from AppArmorProfile",
			"resource version", sp.GetResourceVersion(),
			"name", sp.GetName(),
		)
	}

	return nil
}

// reconcileDisabled unloads a disabled profile, which the node may have
// loaded before it got disabled. Unloading a profile unconfines the processes
// which run with it, so a profile in use by pods stays until they are gone. A
// profile which this node did not load has nothing to unload, even while pods
// on other nodes use it.
func (r *Reconciler) reconcileDisabled(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	return common.ReconcileDisabled(
		ctx, sp, nodeStatus, l, r.errorReporter(sp.GetName()), deletionReasons(),
		common.Removal{
			// A status of an earlier release which did not record the
			// installation yet only tells it by its state. A profile which
			// got loaded without the installation being recorded, like
			// when the record failed, is told by the ownership marker of
			// its policy file.
			Installed: func(state secprofnodestatusapi.ProfileState) (bool, error) {
				if state == secprofnodestatusapi.ProfileStateInstalled {
					return true, nil
				}

				installed, err := nodeStatus.GetAnnotation(ctx, installedAnnotation)
				if err != nil || installed == "true" {
					return installed == "true", err
				}

				return r.manager.ProfileInstalled(sp)
			},
			// This only removes a profile which this operator installed.
			Remove: func() (reconcile.Result, error) {
				return reconcile.Result{}, r.handleDeletion(ctx, sp, nodeStatus, l)
			},
			// The profile is not ours anymore until it gets installed again.
			AfterRemove: func() error {
				return nodeStatus.SetAnnotation(ctx, installedAnnotation, "")
			},
		},
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
		r.errorReporter(sp.GetName()),
		deletionReasons(),
		func() (reconcile.Result, error) { return reconcile.Result{}, r.handleDeletion(ctx, sp, nsc, l) },
	)
}

func (r *Reconciler) handleDeletion(
	ctx context.Context,
	sp *apparmorprofileapi.AppArmorProfile,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) error {
	// The profiles of the operator are never loaded for an AppArmorProfile,
	// see installProfile, and removing them would break its containers.
	if isOperatorProfile(sp.GetProfileName()) {
		l.Info("Keeping the profile of the operator", "profile", sp.GetProfileName())

		return nil
	}

	installed, err := nodeStatus.GetAnnotation(ctx, installedAnnotation)
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("checking if the profile was installed on this node: %w", err)
	}

	removed, err := r.manager.RemoveProfile(sp, installed == "true")
	if err != nil {
		return fmt.Errorf("unloading profile from host: %w", err)
	}

	// Nothing got removed for a profile which never got installed here, for
	// example because it conflicts with a profile of the host.
	if removed {
		l.Info("removed profile", "profile", sp.GetProfileName())
		r.metrics.IncAppArmorProfileDelete()
	}

	return nil
}
