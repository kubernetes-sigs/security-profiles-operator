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

package selinuxprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	selinuxdSockAddr        = "http://unix"
	selinuxdPoliciesBaseURL = selinuxdSockAddr + "/policies/"
	selinuxdReadyURL        = selinuxdSockAddr + "/ready"

	selinuxdReadyKey     = "ready"
	selinuxdPollInterval = 5 * time.Second
	reconcileTimeout     = time.Minute

	// inheritRetryInterval is the time after which a profile whose inherited
	// profile does not exist is checked again.
	inheritRetryInterval = 30 * time.Second
)

type sePolStatusType string

const (
	installedStatus sePolStatusType = "Installed"
	failedStatus    sePolStatusType = "Failed"
)

type sePolStatus struct {
	Msg    string          `json:"msg"`
	Status sePolStatusType `json:"status"`
}

const (
	reasonCannotContactSelinuxd    string = "CannotContactSelinuxd"
	reasonCannotRemovePolicy       string = "CannotRemoveSelinuxPolicy"
	reasonCannotInstallPolicy      string = "CannotSaveSelinuxPolicy"
	reasonSystemModuleConflict     string = "SystemModuleConflict"
	reasonCannotWritePolicyFile    string = "CannotWritePolicyFile"
	reasonCannotGetPolicyStatus    string = "CannotGetPolicyStatus"
	reasonCannotUpdatePolicyStatus string = "CannotUpdatePolicyStatus"
	reasonInstalledPolicy          string = "SavedSelinuxPolicy"
	reasonCannotReloadPolicy       string = "CannotReloadSelinuxPolicy"
)

const (
	reloadInstallGenerationAnnotation = "spo.x-k8s.io/selinux-policy-reload-generation"
	reloadRemoveGenerationAnnotation  = "spo.x-k8s.io/selinux-policy-reload-remove-generation"
)

// blank assignment to verify that ReconcileSelinux implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSelinux{}

var (
	// errPolicyNotFound is returned if no policy has been found.
	errPolicyNotFound = errors.New("policy not found")

	// errPolicyRemovalFailed is returned if selinuxd failed to remove a policy.
	errPolicyRemovalFailed = errors.New("selinuxd failed to remove the policy")

	// errInheritedProfileUnusable is returned if an inherited profile cannot
	// get installed.
	errInheritedProfileUnusable = errors.New("inherited profile cannot be installed")
)

// ReconcileSelinux reconciles a Selinux profile objects.
type ReconcileSelinux struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client client.Client
	// clientReader reads objects directly from api-server, this is useful when
	// the cache is filtered or otherwise not expected to contain an object.
	clientReader      client.Reader
	scheme            *runtime.Scheme
	record            util.EventRecorder
	metrics           *metrics.Metrics
	log               logr.Logger
	controllerName    string
	objectHandlerInit SelinuxObjectHandlerInit
	ctrlBuilder       controllerBuilder
	httpc             *http.Client
	// moduleStorePath overrides the host SELinux module store for testing.
	moduleStorePath string
	// policyDir overrides the directory selinuxd picks up policies from for
	// testing.
	policyDir string
	// nodeName is the name of the node the daemon runs on.
	nodeName string
}

func (r *ReconcileSelinux) policyPath(sp selinuxprofileapi.SelinuxProfileObject) string {
	dir := bindata.SelinuxDropDirectory
	if r.policyDir != "" {
		dir = r.policyDir
	}

	return filepath.Join(dir, filepath.Clean(sp.GetPolicyName()+".cil"))
}

func (r *ReconcileSelinux) selinuxModuleStorePath() string {
	if r.moduleStorePath != "" {
		return r.moduleStorePath
	}

	return bindata.SelinuxModuleStorePath
}

// Setup adds a controller that reconciles selinux profiles.
func (r *ReconcileSelinux) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.log = logf.Log.WithName(r.controllerName)
	r.client = mgr.GetClient()
	r.clientReader = mgr.GetAPIReader()
	r.scheme = mgr.GetScheme()
	r.record = util.NewEventRecorder(mgr, r.controllerName)
	r.metrics = met
	r.nodeName = os.Getenv(config.NodeNameEnvKey)
	r.httpc = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", bindata.SelinuxdSocketPath)
			},
		},
	}

	return r.ctrlBuilder(ctrl.NewControllerManagedBy(mgr), r)
}

// Name returns the name of the controller.
func (r *ReconcileSelinux) Name() string {
	return r.controllerName + "-spod"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReconcileSelinux) SchemeBuilder() runtime.SchemeBuilder {
	return selinuxprofileapi.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *ReconcileSelinux) Healthz(req *http.Request) error {
	ready, err := isSelinuxdReady(req.Context(), r.httpc)
	if err != nil {
		return fmt.Errorf("getting health status: %w", err)
	}

	if !ready {
		return errors.New("not ready")
	}

	return nil
}

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=delete;get;update;patch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=delete;get;update;patch

// The policy reload Job is only ever created in the operator namespace, see
// createPolicyReloadJob. Keeping this namespaced prevents a compromised node
// from creating a Job with an arbitrary service account anywhere in the cluster.
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=batch,namespace="security-profiles-operator",resources=jobs,verbs=create;delete;get;list;watch

// Reconcile reads that state of the cluster for a SelinuxProfile object and makes changes based on the state read
// and what is in the `SelinuxProfile.Spec`.
func (r *ReconcileSelinux) Reconcile(
	ctx context.Context,
	request reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	reqLogger := r.log.WithValues("profile", request.Name)
	reqLogger.Info("Reconciling object", "controller", r.controllerName)

	// Fetch the object instance
	oh, err := r.objectHandlerInit(ctx, r.client, request.NamespacedName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			// The object is gone. Continuing here would operate on the
			// zero-valued object the handler allocated and drive a reconcile
			// against an empty key, which can only fail and requeue forever.
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, err
	}

	instance := oh.GetProfileObject()

	nodeStatus, err := nodestatus.NewForProfileOnNode(instance, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus instance: %w", err)
	}

	if !instance.GetDeletionTimestamp().IsZero() {
		return common.ReconcileDeletion(
			ctx, instance, nodeStatus, r.client, reqLogger, r.record,
			common.DeletionReasons{
				CannotUpdateProfile: reasonCannotUpdatePolicyStatus,
				CannotRemoveProfile: reasonCannotRemovePolicy,
				CannotUpdateStatus:  reasonCannotUpdatePolicyStatus,
			},
			r.metrics.IncSelinuxProfileError,
			func() (reconcile.Result, error) {
				return r.reconcileDeletePolicy(ctx, instance, nodeStatus, reqLogger)
			},
		)
	}

	// Unlike the other profile kinds, the policy is installed in the same
	// pass that creates the node status.
	if _, _, err := common.EnsureNodeStatus(ctx, nodeStatus, reqLogger); err != nil {
		return reconcile.Result{}, err
	}

	return r.reconcilePolicy(ctx, instance, oh, nodeStatus, reqLogger)
}

// reportError increments the error metric for reason and records a warning
// event with the message on obj.
func (r *ReconcileSelinux) reportError(obj runtime.Object, reason, action, msg string) {
	common.ErrorReporter{
		Record:   r.record,
		IncError: r.metrics.IncSelinuxProfileError,
	}.Report(obj, reason, action, msg)
}

func (r *ReconcileSelinux) reconcilePolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady(ctx, r.httpc)
	if err != nil {
		r.reportError(sp, reasonCannotContactSelinuxd, util.EventActionInstall, err.Error())

		return reconcile.Result{}, fmt.Errorf("contacting selinuxd: %w", err)
	}

	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			reasonCannotContactSelinuxd,
			util.EventActionInstall,
			"selinuxd not yet ready",
		)

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	}

	if valErr := oh.Validate(ctx); valErr != nil {
		return r.handleValidationError(ctx, sp, nodeStatus, valErr)
	}

	if !sp.IsReconcilable() {
		l.Info("Profile is partial or disabled, skipping")

		return reconcile.Result{}, nil
	}

	conflict, err := r.conflictsWithSystemModule(ctx, sp, nodeStatus)
	if err != nil {
		return reconcile.Result{}, err
	}

	if conflict {
		if err := r.setNodeStatus(
			ctx,
			sp,
			nodeStatus,
			secprofnodestatusapi.ProfileStateError,
		); err != nil {
			return reconcile.Result{}, err
		}

		evstr := fmt.Sprintf(
			"Profile name %q conflicts with a system SELinux module on %s; "+
				"use a different name (e.g. %q)",
			sp.GetPolicyName(), r.nodeName, "custom-"+sp.GetPolicyName(),
		)

		r.reportError(sp, reasonSystemModuleConflict, util.EventActionInstall, evstr)

		return reconcile.Result{}, nil
	}

	// The policy inherits the blocks of its ancestors, so it can only be
	// installed after them.
	installed, err := r.inheritedProfilesInstalled(ctx, oh, l)
	if errors.Is(err, errInheritedProfileUnusable) {
		if err := r.setNodeStatus(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateError,
		); err != nil {
			return reconcile.Result{}, err
		}

		r.reportError(sp, reasonCannotInstallPolicy, util.EventActionInstall, fmt.Sprintf(
			"Profile cannot be installed on %s: %s", r.nodeName, err.Error(),
		))

		// The inherited profile may still be fixed.
		return reconcile.Result{RequeueAfter: inheritRetryInterval}, nil
	}

	if err != nil {
		return reconcile.Result{}, fmt.Errorf("checking inherited profiles: %w", err)
	}

	// The state stays pending, because nothing got installed yet, see
	// conflictsWithSystemModule.
	if !installed {
		if err := r.setNodeStatus(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStatePending,
		); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: common.Wait}, nil
	}

	policyUpdated, err := r.reconcilePolicyFile(sp, oh, l)
	if err != nil {
		r.reportError(sp, reasonCannotWritePolicyFile, util.EventActionInstall, err.Error())

		return reconcile.Result{}, fmt.Errorf("creating policy file: %w", err)
	}

	// If the policy file was just updated, requeue to give selinuxd time to detect
	// the change and reinstall the policy before we check status and trigger reload.
	// Without this, we might trigger the reload job before selinuxd has processed the update.
	if policyUpdated {
		l.Info("Policy file updated, requeuing to allow selinuxd to process the change")

		if err := r.setNodeStatus(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateInProgress,
		); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	}

	l.Info("Checking if policy deployed", "policyName", sp.GetName())
	polStatus, err := getPolicyStatus(ctx, sp, r.httpc)

	if errors.Is(err, errPolicyNotFound) {
		if err := r.setNodeStatus(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateInProgress,
		); err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	}

	if err != nil {
		r.reportError(sp, reasonCannotGetPolicyStatus, util.EventActionInstall, err.Error())

		return reconcile.Result{}, fmt.Errorf("looking up policy status: %w", err)
	}

	var polState secprofnodestatusapi.ProfileState

	switch polStatus.Status {
	case installedStatus:
		polState = secprofnodestatusapi.ProfileStateInstalled
		evstr := "Successfully saved profile to disk on " + r.nodeName

		r.metrics.IncSelinuxProfileUpdate()
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeNormal,
			reasonInstalledPolicy,
			util.EventActionInstall,
			"%s",
			evstr,
		)

		r.reloadInstalledPolicy(ctx, sp, nodeStatus, l)
	case failedStatus:
		polState = secprofnodestatusapi.ProfileStateError
		evstr := fmt.Sprintf(
			"Failed to save profile to disk on %s: %s",
			r.nodeName,
			polStatus.Msg,
		)

		r.reportError(sp, reasonCannotInstallPolicy, util.EventActionInstall, evstr)
	}

	l.Info("Policy deployed", "status", polState)

	if err := r.setNodeStatus(ctx, sp, nodeStatus, polState); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// conflictsWithSystemModule returns true if a module with the name of the
// policy is installed on the node which this operator did not install. The
// module is ours if the policy file is on disk, or if the node status shows
// that the policy got installed on the node before, for example by a SPOd pod
// which has been replaced since. The node status moves past pending only
// after the policy file got written.
func (r *ReconcileSelinux) conflictsWithSystemModule(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
) (bool, error) {
	if !isSELinuxModuleInstalled(r.selinuxModuleStorePath(), filepath.Clean(sp.GetPolicyName())) {
		return false, nil
	}

	if _, err := os.Stat(r.policyPath(sp)); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("checking policy file: %w", err)
	}

	state, err := nodeStatus.State(ctx)
	if err != nil && !kerrors.IsNotFound(err) {
		return false, fmt.Errorf("getting node status: %w", err)
	}

	switch state {
	case secprofnodestatusapi.ProfileStateInProgress,
		secprofnodestatusapi.ProfileStateInstalled,
		secprofnodestatusapi.ProfileStateTerminating:
		return false, nil
	case secprofnodestatusapi.ProfileStatePending,
		secprofnodestatusapi.ProfileStateError,
		secprofnodestatusapi.ProfileStatePartial,
		secprofnodestatusapi.ProfileStateDisabled:
		return true, nil
	default:
		return true, nil
	}
}

// setNodeStatus sets the node status and reports a failure.
func (r *ReconcileSelinux) setNodeStatus(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	state secprofnodestatusapi.ProfileState,
) error {
	if err := nodeStatus.SetNodeStatus(ctx, state); err != nil {
		r.reportError(sp, reasonCannotUpdatePolicyStatus, util.EventActionUpdate, err.Error())

		return fmt.Errorf("setting node status to %s: %w", state, err)
	}

	return nil
}

// handleValidationError marks a profile which failed validation. Failures
// caused by the API server are retried with backoff, and a missing inherited
// profile is checked again later, because it may still be created.
func (r *ReconcileSelinux) handleValidationError(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	valErr error,
) (reconcile.Result, error) {
	if errors.Is(valErr, errTemporaryValidation) {
		return reconcile.Result{}, fmt.Errorf("validating profile: %w", valErr)
	}

	if err := r.setNodeStatus(
		ctx,
		sp,
		nodeStatus,
		secprofnodestatusapi.ProfileStateError,
	); err != nil {
		return reconcile.Result{}, err
	}

	evstr := fmt.Sprintf("Profile failed validation on %s: %s", r.nodeName, valErr.Error())
	r.reportError(sp, reasonCannotInstallPolicy, util.EventActionInstall, evstr)

	if errors.Is(valErr, ErrInheritNotFound) {
		return reconcile.Result{RequeueAfter: inheritRetryInterval}, nil
	}

	return reconcile.Result{}, nil
}

// inheritingHandler is implemented by object handlers whose policies inherit
// from other profiles of the operator.
type inheritingHandler interface {
	inheritedProfiles() []selinuxprofileapi.SelinuxProfileObject
}

// inheritedProfilesInstalled returns true if every profile of the operator
// which the policy inherits from is installed on this node.
func (r *ReconcileSelinux) inheritedProfilesInstalled(
	ctx context.Context, oh SelinuxObjectHandler, l logr.Logger,
) (bool, error) {
	ih, ok := oh.(inheritingHandler)
	if !ok {
		return true, nil
	}

	for _, ancestor := range ih.inheritedProfiles() {
		// A profile which is not installed now will never be without a change.
		if !ancestor.IsReconcilable() || !ancestor.GetDeletionTimestamp().IsZero() {
			return false, fmt.Errorf(
				"%w: %s is disabled, partial or being deleted",
				errInheritedProfileUnusable, ancestor.GetName(),
			)
		}

		nsc, err := nodestatus.NewForProfileOnNode(ancestor, r.client, r.nodeName)
		if err != nil {
			return false, fmt.Errorf(
				"creating node status client for %s: %w",
				ancestor.GetName(),
				err,
			)
		}

		state, err := nsc.State(ctx)
		if err != nil && !kerrors.IsNotFound(err) {
			return false, fmt.Errorf("getting node status of %s: %w", ancestor.GetName(), err)
		}

		if state == secprofnodestatusapi.ProfileStateError {
			return false, fmt.Errorf(
				"%w: %s failed to install", errInheritedProfileUnusable, ancestor.GetName(),
			)
		}

		if state != secprofnodestatusapi.ProfileStateInstalled {
			l.Info("Waiting for inherited profile to be installed", "inherited", ancestor.GetName())

			return false, nil
		}
	}

	return true, nil
}

// reloadInstalledPolicy creates a job which reloads the kernel policy after
// the installation of a new policy generation. On RHEL 9 and OpenShift 4.20+,
// semodule -i no longer reloads the in-memory policy. A failure does not fail
// the reconcile: the policy is installed, just not reloaded yet.
func (r *ReconcileSelinux) reloadInstalledPolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) {
	reloadGeneration := strconv.FormatInt(sp.GetGeneration(), 10)

	lastReloadGeneration, err := nodeStatus.GetAnnotation(ctx, reloadInstallGenerationAnnotation)
	if err != nil {
		l.Error(err, "Failed to read reload generation annotation")
	}

	if lastReloadGeneration == reloadGeneration {
		l.Info("Reload already performed for policy generation, skipping",
			"generation", reloadGeneration, "policyName", sp.GetPolicyName())

		return
	}

	jobCreated, err := r.createPolicyReloadJob(ctx, sp.GetPolicyName(), "install", l)
	if err != nil {
		l.Error(
			err,
			"Failed to create policy reload job, policy may not be active until manual reload",
		)
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			reasonCannotReloadPolicy,
			util.EventActionInstall,
			"Failed to create policy reload job on %s: %s",
			r.nodeName,
			err.Error(),
		)

		return
	}

	// If no job was created because a recent one exists, the annotation is
	// left alone so that the next reconcile retries.
	if !jobCreated {
		return
	}

	if err := nodeStatus.SetAnnotation(
		ctx,
		reloadInstallGenerationAnnotation,
		reloadGeneration,
	); err != nil {
		l.Error(err, "Failed to set reload generation annotation")
	}
}

// reconcilePolicyFile writes the policy file to the drop directory if the content differs.
// Returns (policyUpdated, error) where policyUpdated is true if the file was actually written.
func (r *ReconcileSelinux) reconcilePolicyFile(
	sp selinuxprofileapi.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	l logr.Logger,
) (bool, error) {
	policyPath := r.policyPath(sp)

	cil, parseErr := oh.GetCILPolicy()
	if parseErr != nil {
		return false, fmt.Errorf("generating CIL: %w", parseErr)
	}

	policyContent := []byte(cil)

	written, err := writeFileIfDiffers(policyPath, policyContent, l)
	if err != nil {
		return false, fmt.Errorf("writing policy file: %w", err)
	}

	return written, nil
}

func (r *ReconcileSelinux) reconcileDeletePolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	selinuxdReady, err := isSelinuxdReady(ctx, r.httpc)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("contacting selinuxd: %w", err)
	}

	if !selinuxdReady {
		l.Info("selinuxd not yet up, requeue")

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	}

	res, err := r.reconcileDeletePolicyFile(sp, l)
	if res.RequeueAfter > 0 || err != nil {
		return res, err
	}

	l.Info("Checking if policy is removed", "policyName", sp.GetName())
	polStatus, err := getPolicyStatus(ctx, sp, r.httpc)

	if errors.Is(err, errPolicyNotFound) {
		// Policy was successfully removed, trigger a reload to update kernel policy
		reloadGeneration := strconv.FormatInt(sp.GetGeneration(), 10)

		lastReloadGeneration, err := nodeStatus.GetAnnotation(ctx, reloadRemoveGenerationAnnotation)
		if err != nil {
			l.Error(err, "Failed to read reload generation annotation after removal")
		}

		if lastReloadGeneration == reloadGeneration {
			l.Info("Reload already performed for policy removal, skipping",
				"generation", reloadGeneration, "policyName", sp.GetPolicyName())
		} else {
			jobCreated, err := r.createPolicyReloadJob(ctx, sp.GetPolicyName(), "remove", l)
			if err != nil {
				l.Error(err, "Failed to create policy reload job after removal")
				r.record.Eventf(
					sp,
					nil,
					util.EventTypeWarning,
					reasonCannotReloadPolicy,
					util.EventActionRemove,
					"%s",
					fmt.Sprintf("Failed to create policy reload job after removal on %s: %s",
						r.nodeName, err.Error()),
				)
			} else if jobCreated {
				if err := nodeStatus.SetAnnotation(
					ctx,
					reloadRemoveGenerationAnnotation,
					reloadGeneration,
				); err != nil {
					l.Error(err, "Failed to set reload generation annotation after removal")
				}
			}
		}

		return reconcile.Result{}, nil
	}

	if err != nil {
		r.metrics.IncSelinuxProfileError(reasonCannotGetPolicyStatus)

		return reconcile.Result{}, fmt.Errorf("looking up policy status: %w", err)
	}

	switch polStatus.Status {
	case installedStatus:
		l.Info("Policy still installed, requeue")

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	case failedStatus:
		// selinuxd keeps a Failed status from an earlier install until it
		// processes the removal of the policy file, and it keeps the last
		// status if removing the module fails. The removal is only done
		// once the module is gone from the module store.
		policyName := filepath.Clean(sp.GetPolicyName())
		if isSELinuxModuleInstalled(r.selinuxModuleStorePath(), policyName) {
			return reconcile.Result{}, fmt.Errorf(
				"%w %s on %s: %s",
				errPolicyRemovalFailed,
				sp.GetPolicyName(),
				r.nodeName,
				polStatus.Msg,
			)
		}

		l.Info("Policy reported as failed but the module is not installed")
	}

	r.metrics.IncSelinuxProfileDelete()
	l.Info("Policy removed")

	return reconcile.Result{}, nil
}

func (r *ReconcileSelinux) reconcileDeletePolicyFile(sp selinuxprofileapi.SelinuxProfileObject,
	l logr.Logger,
) (reconcile.Result, error) {
	policyPath := r.policyPath(sp)

	l.Info("Removing policy file", "policyPath", policyPath)

	err := os.Remove(policyPath)
	if err == nil {
		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
	}

	if osPathErr, ok := errors.AsType[*os.PathError](err); ok {
		if errors.Is(osPathErr.Err, os.ErrNotExist) {
			return reconcile.Result{}, nil
		}
	}

	return reconcile.Result{RequeueAfter: selinuxdPollInterval},
		fmt.Errorf("error removing policy file: %w", err)
}

func getPolicyStatus(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	httpc *http.Client,
) (*sePolStatus, error) {
	polURL := selinuxdPoliciesBaseURL + sp.GetPolicyName()

	response, err := selinuxdGetRequest(ctx, httpc, polURL)
	if err != nil {
		return nil, fmt.Errorf("failed to send a request to selinuxd: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, errPolicyNotFound
	} else if response.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected HTTP error code " + strconv.Itoa(response.StatusCode))
	}

	var status sePolStatus

	err = json.NewDecoder(response.Body).Decode(&status)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response from selinuxd: %w", err)
	}

	switch status.Status {
	case installedStatus, failedStatus:
		return &status, nil
	}

	return nil, errors.New("invalid sePolStatus value")
}

func isSelinuxdReady(ctx context.Context, httpc *http.Client) (bool, error) {
	response, err := selinuxdGetRequest(ctx, httpc, selinuxdReadyURL)
	if err != nil {
		return false, fmt.Errorf("failed to send a request to selinuxd: %w", err)
	}
	defer response.Body.Close()

	var status map[string]bool

	err = json.NewDecoder(response.Body).Decode(&status)
	if err != nil {
		return false, fmt.Errorf("failed to decode response from selinuxd: %w", err)
	}

	return status[selinuxdReadyKey], nil
}

func selinuxdGetRequest(
	ctx context.Context,
	httpc *http.Client,
	url string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request to selinuxd: %w", err)
	}

	return httpc.Do(req)
}

// writeFileIfDiffers checks if the content of file at filePath are the same as the byte array
// contents, if not, overwrites the file at filePath.
// Returns (written, error) where written is true if the file was actually written
// (content differed or file didn't exist).
//
// Reopening the same file may seem wasteful and even look like a TOCTOU issue, but the policy
// drop dir is private to this pod, but mostly just calling a single write is much easier codepath
// than mucking around with seeks and truncates to account for all the corner cases.
func writeFileIfDiffers(filePath string, contents []byte, l logr.Logger) (bool, error) {
	const filePermissions = 0o600

	file, err := os.OpenFile(filePath, os.O_RDONLY, filePermissions)
	if os.IsNotExist(err) {
		l.Info("Writing new policy file", "policyPath", filePath)

		return true, util.WriteFileAtomic(filePath, contents, filePermissions)
	} else if err != nil {
		return false, fmt.Errorf("could not open for reading %s: %w", filePath, err)
	}

	defer file.Close()

	const maxPolicyFileSize = 10 * 1024 * 1024 // 10MB

	existing, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize))
	if err != nil {
		return false, fmt.Errorf("reading file %s: %w", filePath, err)
	}

	if bytes.Equal(existing, contents) {
		return false, nil
	}

	l.Info("Updating policy file", "policyPath", filePath)

	return true, util.WriteFileAtomic(filePath, contents, filePermissions)
}

// isSELinuxModuleInstalled checks whether an SELinux module with the given name
// is installed in the host's module store. The store layout is
// /var/lib/selinux/<policy_type>/active/modules/<priority>/<module_name>/.
func isSELinuxModuleInstalled(moduleStorePath, name string) bool {
	policyTypes, err := os.ReadDir(moduleStorePath)
	if err != nil {
		return false
	}

	for _, pt := range policyTypes {
		if !pt.IsDir() {
			continue
		}

		modulesDir := filepath.Join(moduleStorePath, pt.Name(), "active", "modules")

		priorities, err := os.ReadDir(modulesDir)
		if err != nil {
			continue
		}

		for _, prio := range priorities {
			if !prio.IsDir() {
				continue
			}

			moduleDir := filepath.Join(modulesDir, prio.Name(), name)
			if fi, err := os.Stat(moduleDir); err == nil && fi.IsDir() {
				return true
			}
		}
	}

	return false
}
