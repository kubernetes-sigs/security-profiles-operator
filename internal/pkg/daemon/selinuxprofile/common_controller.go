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
	"sync"
	"time"

	"github.com/go-logr/logr"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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
	reasonPolicyNameConflict       string = "SelinuxPolicyNameConflict"
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
	// namespace is the namespace of the operator, which runs the reload
	// jobs.
	namespace string
	// podName is the name of the SPOd pod the daemon runs in.
	podName string

	// reportedMu guards reported.
	reportedMu sync.Mutex
	// reported is the last error which keeps a profile from being
	// installed, per profile, see reportInstallError.
	reported map[types.NamespacedName]installError

	// reloadFailuresMu guards reloadFailures.
	reloadFailuresMu sync.Mutex
	// reloadFailures counts the failed install reload jobs of the current
	// generation, per profile, see reloadRetryDelay.
	reloadFailures map[types.NamespacedName]reloadFailures

	// removalsCounted maps the profiles whose removal got counted in the
	// metrics to their UID, as a retried deletion or the deletion of a
	// disabled profile counts it again otherwise. The node status, which
	// records the reload, may be gone already. An installation forgets the
	// counted removal, so that the next removal counts again.
	removalsCounted sync.Map
}

// installError is an error which keeps a generation of a profile from being
// installed.
type installError struct {
	generation int64
	reason     string
	msg        string
}

// policyDirectory returns the directory selinuxd picks up policies from.
func (r *ReconcileSelinux) policyDirectory() string {
	if r.policyDir != "" {
		return r.policyDir
	}

	return bindata.SelinuxDropDirectory
}

func (r *ReconcileSelinux) policyPath(sp selinuxprofileapi.SelinuxProfileObject) string {
	return filepath.Join(r.policyDirectory(), filepath.Clean(sp.GetPolicyName()+".cil"))
}

// existenceChangedPredicate passes the creation and removal of objects.
var existenceChangedPredicate = predicate.Funcs{
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
}

// kindOf returns the kind of a profile. Objects read without the cache do
// not carry their TypeMeta.
func kindOf(sp selinuxprofileapi.SelinuxProfileObject) string {
	switch sp.(type) {
	case *selinuxprofileapi.SelinuxProfile:
		return "SelinuxProfile"
	case *selinuxprofileapi.RawSelinuxProfile:
		return "RawSelinuxProfile"
	}

	return sp.GetObjectKind().GroupVersionKind().Kind
}

// otherKind returns an empty profile of the kind which shares policy names
// with sp: a SelinuxProfile and a RawSelinuxProfile of the same name get the
// same policy name, and so the same policy file and module.
func otherKind(sp selinuxprofileapi.SelinuxProfileObject) selinuxprofileapi.SelinuxProfileObject {
	switch sp.(type) {
	case *selinuxprofileapi.SelinuxProfile:
		return &selinuxprofileapi.RawSelinuxProfile{}
	case *selinuxprofileapi.RawSelinuxProfile:
		return &selinuxprofileapi.SelinuxProfile{}
	}

	return nil
}

// ownsPolicyBefore returns true if profile a takes precedence over profile b
// for the policy name they share. The profile created first owns it, on a tie
// the SelinuxProfile.
func ownsPolicyBefore(a, b selinuxprofileapi.SelinuxProfileObject) bool {
	ta, tb := a.GetCreationTimestamp(), b.GetCreationTimestamp()
	if !ta.Equal(&tb) {
		return ta.Before(&tb)
	}

	_, isSelinuxProfile := a.(*selinuxprofileapi.SelinuxProfile)

	return isSelinuxProfile
}

// policyOwner returns the profile of the other kind which owns the policy of
// sp, and false if sp owns it. Unlike a seccomp profile, a disabled profile or
// one which is being deleted keeps the policy: the other profile only takes it
// over once the owner removed the policy from the nodes and is gone, so that
// the removal cannot delete the policy of the other profile. The cache is
// enough: the creation and removal of the other profile enqueue sp again.
func (r *ReconcileSelinux) policyOwner(
	ctx context.Context, sp selinuxprofileapi.SelinuxProfileObject,
) (owner selinuxprofileapi.SelinuxProfileObject, found bool, err error) {
	other := otherKind(sp)
	if other == nil {
		return nil, false, nil
	}

	if err := r.client.Get(ctx, client.ObjectKeyFromObject(sp), other); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("looking up %s %s: %w", kindOf(other), sp.GetName(), err)
	}

	if ownsPolicyBefore(sp, other) {
		return nil, false, nil
	}

	return other, true, nil
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
	r.podName = os.Getenv(config.PodNameEnvKey)

	namespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("getting the operator namespace: %w", err)
	}

	r.namespace = namespace
	r.httpc = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", bindata.SelinuxdSocketPath)
			},
		},
	}

	common.RemoveStaleTempFiles(r.log, r.policyDirectory())

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

// The daemon updates the finalizers and labels of the profiles, and the
// profile recorder creates recorded SelinuxProfiles. The profile status is
// written by the manager. The finalizers subresource allows the node statuses
// to block the deletion of their owner profile.
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=get;update;patch

//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch

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
	reqLogger.V(config.VerboseLevel).Info("Reconciling object", "controller", r.controllerName)

	// Fetch the object instance
	oh, err := r.objectHandlerInit(ctx, r.client, request.NamespacedName, r.namespace)
	if err != nil {
		if kerrors.IsNotFound(err) {
			// The object is gone. Continuing here would operate on the
			// zero-valued object the handler allocated and drive a reconcile
			// against an empty key, which can only fail and requeue forever.
			r.forgetProfile(request.NamespacedName)

			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, err
	}

	instance := oh.GetProfileObject()

	nodeStatus, err := nodestatus.NewForProfileOnNode(instance, r.client, r.nodeName)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot create nodeStatus instance: %w", err)
	}

	nodeStatus.WithAPIReader(r.clientReader)

	if !instance.GetDeletionTimestamp().IsZero() {
		// The counted removal is kept until the profile is gone, a retry
		// must not count it again.
		r.forgetInstallError(request.NamespacedName)
		r.forgetReloadFailures(request.NamespacedName)

		return common.ReconcileDeletion(
			ctx, instance, nodeStatus, r.client, reqLogger, r.record,
			common.DeletionReasons{
				CannotUpdateProfile: reasonCannotUpdatePolicyStatus,
				CannotRemoveProfile: reasonCannotRemovePolicy,
				CannotUpdateStatus:  reasonCannotUpdatePolicyStatus,
			},
			r.metrics.IncSelinuxProfileError,
			func() (reconcile.Result, error) {
				owner, found, err := r.policyOwner(ctx, instance)
				if err != nil {
					return reconcile.Result{}, err
				}

				if found {
					reqLogger.Info("Keeping the policy of another profile",
						"kind", kindOf(owner), "name", owner.GetName())

					return reconcile.Result{}, nil
				}

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

// reportInstallError reports an error which keeps the profile from being
// installed, unless it is the error reported last for the generation of the
// profile. Nothing but a change of the profile or of the node fixes it, while
// the periodic resyncs of the daemon cache reconcile the profile again and
// again.
func (r *ReconcileSelinux) reportInstallError(
	sp selinuxprofileapi.SelinuxProfileObject, reason, msg string,
) {
	key := client.ObjectKeyFromObject(sp)
	report := installError{generation: sp.GetGeneration(), reason: reason, msg: msg}

	r.reportedMu.Lock()

	duplicate := r.reported[key] == report
	if !duplicate {
		if r.reported == nil {
			r.reported = map[types.NamespacedName]installError{}
		}

		r.reported[key] = report
	}

	r.reportedMu.Unlock()

	if duplicate {
		return
	}

	r.reportError(sp, reason, util.EventActionInstall, msg)
}

// forgetInstallError forgets the error reported last for the profile, which
// got installed or is gone.
func (r *ReconcileSelinux) forgetInstallError(key types.NamespacedName) {
	r.reportedMu.Lock()
	defer r.reportedMu.Unlock()

	delete(r.reported, key)
}

// forgetProfile forgets what got remembered about a profile which is gone.
func (r *ReconcileSelinux) forgetProfile(key types.NamespacedName) {
	r.forgetInstallError(key)
	r.forgetReloadFailures(key)
	r.removalsCounted.Delete(key)
}

func (r *ReconcileSelinux) reconcilePolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	if res, done, err := r.checkPreconditions(ctx, sp, oh, nodeStatus, l); done {
		return res, err
	}

	if conflict, err := r.checkConflicts(ctx, sp, nodeStatus); conflict || err != nil {
		return reconcile.Result{}, err
	}

	if res, done, err := r.waitForAncestors(ctx, sp, oh, nodeStatus, l); done {
		return res, err
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

		return r.waitForSelinuxd(ctx, sp, nodeStatus)
	}

	return r.handlePolicyStatus(ctx, sp, nodeStatus, l)
}

// waitForSelinuxd marks the policy as being installed and checks again after
// selinuxdPollInterval.
func (r *ReconcileSelinux) waitForSelinuxd(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
) (reconcile.Result, error) {
	if err := r.setNodeStatus(
		ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateInProgress,
	); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{RequeueAfter: selinuxdPollInterval}, nil
}

// checkPreconditions returns true with the result of the reconcile if the
// policy is not to be installed now: selinuxd is not ready, the profile is
// disabled, partial or invalid.
func (r *ReconcileSelinux) checkPreconditions(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, bool, error) {
	selinuxdReady, err := isSelinuxdReady(ctx, r.httpc)
	if err != nil {
		r.reportError(sp, reasonCannotContactSelinuxd, util.EventActionInstall, err.Error())

		return reconcile.Result{}, true, fmt.Errorf("contacting selinuxd: %w", err)
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

		return reconcile.Result{RequeueAfter: selinuxdPollInterval}, true, nil
	}

	if sp.IsDisabled() && !sp.IsPartial() {
		res, err := r.reconcileDisabledPolicy(ctx, sp, nodeStatus, l)

		return res, true, err
	}

	if valErr := oh.Validate(ctx); valErr != nil {
		res, err := r.handleValidationError(ctx, sp, nodeStatus, valErr)

		return res, true, err
	}

	if !sp.IsReconcilable() {
		l.Info("Profile is partial, skipping")

		return reconcile.Result{}, true, nil
	}

	return reconcile.Result{}, false, nil
}

// checkConflicts returns true if the policy name is taken, by a profile of the
// other kind or by a system module. The profile is enqueued again once the
// other profile is gone, and a system module needs a new name.
func (r *ReconcileSelinux) checkConflicts(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
) (bool, error) {
	owner, found, err := r.policyOwner(ctx, sp)
	if err != nil {
		return true, err
	}

	if found {
		msg := fmt.Sprintf(
			"Policy %q of %s %s is already used by %s %s, rename one of them",
			sp.GetPolicyName(), kindOf(sp), sp.GetName(), kindOf(owner), owner.GetName(),
		)

		if err := r.setNodeStatusWithMessage(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateError, msg,
		); err != nil {
			return true, err
		}

		// The watch on the other kind enqueues this profile once the owner
		// is gone.
		r.reportInstallError(sp, reasonPolicyNameConflict, msg)

		return true, nil
	}

	conflict, err := r.conflictsWithSystemModule(ctx, sp, nodeStatus)
	if err != nil {
		return true, err
	}

	if !conflict {
		return false, nil
	}

	msg := fmt.Sprintf(
		"Profile name %q conflicts with a system SELinux module on %s; "+
			"use a different name (e.g. %q)",
		sp.GetPolicyName(), r.nodeName, "custom-"+sp.GetPolicyName(),
	)

	if err := r.setNodeStatusWithMessage(
		ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateError, msg,
	); err != nil {
		return true, err
	}

	r.reportInstallError(sp, reasonSystemModuleConflict, msg)

	return true, nil
}

// waitForAncestors returns true with the result of the reconcile if the
// profiles the policy inherits from are not installed yet: the policy inherits
// their blocks, so it can only be installed after them.
func (r *ReconcileSelinux) waitForAncestors(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	oh SelinuxObjectHandler,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, bool, error) {
	installed, err := r.inheritedProfilesInstalled(ctx, oh, l)
	if errors.Is(err, errInheritedProfileUnusable) {
		msg := fmt.Sprintf("Profile cannot be installed on %s: %s", r.nodeName, err.Error())

		if err := r.setNodeStatusWithMessage(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateError, msg,
		); err != nil {
			return reconcile.Result{}, true, err
		}

		r.reportInstallError(sp, reasonCannotInstallPolicy, msg)

		// The inherited profile may still be fixed.
		return reconcile.Result{RequeueAfter: inheritRetryInterval}, true, nil
	}

	if err != nil {
		return reconcile.Result{}, true, fmt.Errorf("checking inherited profiles: %w", err)
	}

	if installed {
		return reconcile.Result{}, false, nil
	}

	// The state stays pending, because nothing got installed yet, see
	// conflictsWithSystemModule.
	if err := r.setNodeStatus(
		ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStatePending,
	); err != nil {
		return reconcile.Result{}, true, err
	}

	return reconcile.Result{RequeueAfter: common.Wait}, true, nil
}

// handlePolicyStatus records the status of the policy which selinuxd reports
// and reloads an installed policy.
func (r *ReconcileSelinux) handlePolicyStatus(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	l.V(config.VerboseLevel).Info("Checking if policy deployed", "policyName", sp.GetPolicyName())
	polStatus, err := getPolicyStatus(ctx, sp, r.httpc)

	if errors.Is(err, errPolicyNotFound) {
		return r.waitForSelinuxd(ctx, sp, nodeStatus)
	}

	if err != nil {
		r.reportError(sp, reasonCannotGetPolicyStatus, util.EventActionInstall, err.Error())

		return reconcile.Result{}, fmt.Errorf("looking up policy status: %w", err)
	}

	var (
		polState  secprofnodestatusapi.ProfileState
		message   string
		reloadRes reconcile.Result
		reloadErr error
	)

	switch polStatus.Status {
	case installedStatus:
		polState = secprofnodestatusapi.ProfileStateInstalled

		// A retried reload passes here again, which must not report the
		// installation again.
		alreadyInstalled, err := nodeStatus.Matches(ctx, polState)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("getting the current node status: %w", err)
		}

		r.forgetInstallError(client.ObjectKeyFromObject(sp))
		r.removalsCounted.Delete(client.ObjectKeyFromObject(sp))

		if !alreadyInstalled {
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
		}

		reloadRes, reloadErr = r.reloadInstalledPolicy(ctx, sp, nodeStatus, l)
	case failedStatus:
		polState = secprofnodestatusapi.ProfileStateError
		message = fmt.Sprintf(
			"Failed to save profile to disk on %s: %s",
			r.nodeName,
			polStatus.Msg,
		)

		r.reportInstallError(sp, reasonCannotInstallPolicy, message)
	}

	l.V(config.VerboseLevel).Info("Policy deployed", "status", polState)

	if err := r.setNodeStatusWithMessage(ctx, sp, nodeStatus, polState, message); err != nil {
		return reconcile.Result{}, err
	}

	return reloadRes, reloadErr
}

// reconcileDisabledPolicy removes the policy of a disabled profile, which the
// node may have installed before the profile got disabled.
func (r *ReconcileSelinux) reconcileDisabledPolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	state, err := nodeStatus.State(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting node status: %w", err)
	}

	_, statErr := os.Stat(r.policyPath(sp))
	if statErr != nil && !os.IsNotExist(statErr) {
		return reconcile.Result{}, fmt.Errorf("checking policy file: %w", statErr)
	}

	// The node status moves past pending only after the policy file got
	// written, see conflictsWithSystemModule.
	installed := statErr == nil ||
		state == secprofnodestatusapi.ProfileStateInProgress ||
		state == secprofnodestatusapi.ProfileStateInstalled

	if installed {
		_, found, err := r.policyOwner(ctx, sp)
		if err != nil {
			return reconcile.Result{}, err
		}

		// The policy belongs to the other profile.
		installed = !found
	}

	if installed {
		// Removing the module breaks the pods which run with its types.
		if common.InUse(sp) {
			l.Info("Not removing disabled policy which is in use by pods, requeuing")

			return reconcile.Result{RequeueAfter: common.InUseRetry}, nil
		}

		res, err := r.reconcileDeletePolicy(ctx, sp, nodeStatus, l)
		if err != nil {
			r.reportError(sp, reasonCannotRemovePolicy, util.EventActionRemove, err.Error())

			// A requeue returned with an error is ignored by
			// controller-runtime, which retries with backoff instead.
			return reconcile.Result{}, fmt.Errorf("removing disabled policy: %w", err)
		}

		if res.RequeueAfter > 0 {
			return res, nil
		}
	}

	if state != secprofnodestatusapi.ProfileStateDisabled {
		if err := r.setNodeStatus(
			ctx, sp, nodeStatus, secprofnodestatusapi.ProfileStateDisabled,
		); err != nil {
			return reconcile.Result{}, err
		}
	}

	l.Info("Profile is disabled")

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
	return r.setNodeStatusWithMessage(ctx, sp, nodeStatus, state, "")
}

// setNodeStatusWithMessage is setNodeStatus with a message which tells why
// the profile is in the state, see nodestatus.StatusClient.SetNodeStatusWithMessage.
func (r *ReconcileSelinux) setNodeStatusWithMessage(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	state secprofnodestatusapi.ProfileState,
	message string,
) error {
	if err := nodeStatus.SetNodeStatusWithMessage(ctx, state, message); err != nil {
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

	evstr := fmt.Sprintf("Profile failed validation on %s: %s", r.nodeName, valErr.Error())

	if err := r.setNodeStatusWithMessage(
		ctx,
		sp,
		nodeStatus,
		secprofnodestatusapi.ProfileStateError,
		evstr,
	); err != nil {
		return reconcile.Result{}, err
	}

	r.reportInstallError(sp, reasonCannotInstallPolicy, evstr)

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

// errCreateReloadJob is returned if the reload job cannot be created.
var errCreateReloadJob = errors.New("creating policy reload job")

// reloadKind describes the reload of the kernel policy after an installation
// or a removal of the policy.
type reloadKind struct {
	// action is the action label of the reload jobs.
	action string
	// annotation of the node status records the reloaded generation.
	annotation string
	// eventAction is the action of the events about the reload.
	eventAction string
	// waitForCompletion records the reload only once the job completed, and
	// replaces a failed job. Otherwise the reload is recorded once the job
	// exists, even if it failed.
	waitForCompletion bool
}

var (
	// installReload waits for the reload job: until it completed the new
	// policy is not active, and a failed job has to be retried.
	installReload = reloadKind{
		action:            "install",
		annotation:        reloadInstallGenerationAnnotation,
		eventAction:       util.EventActionInstall,
		waitForCompletion: true,
	}

	// removeReload does not hold up the deletion of the profile until the job
	// completed: until then the kernel only keeps the removed module loaded,
	// which nothing uses anymore.
	removeReload = reloadKind{
		action:      "remove",
		annotation:  reloadRemoveGenerationAnnotation,
		eventAction: util.EventActionRemove,
	}
)

// reloadPolicy makes sure that a job reloads the kernel policy once per
// generation of the profile and action, which it records in the annotation of
// the node status. It requeues while a reload job of another generation is
// still running, because it may have started before the change of the policy,
// and while the job of an installation runs. Nothing else triggers a reconcile
// then. A failed job of an installation is deleted, and a new one gets
// created after a backoff, see retryFailedReload. A failure to record the
// reload is returned, so that the reconcile retries: the job carries the
// generation, so the retry does not create another one.
func (r *ReconcileSelinux) reloadPolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	kind reloadKind,
	l logr.Logger,
) (reconcile.Result, error) {
	action, annotation := kind.action, kind.annotation
	generation := sp.GetGeneration()
	reloadGeneration := strconv.FormatInt(generation, 10)

	lastReloadGeneration, err := nodeStatus.GetAnnotation(ctx, annotation)
	if err != nil {
		l.Error(err, "Failed to read reload generation annotation")
	}

	if lastReloadGeneration == reloadGeneration {
		l.V(config.VerboseLevel).Info("Reload already performed for policy generation, skipping",
			"generation", reloadGeneration, "policyName", sp.GetPolicyName(), "action", action)

		return reconcile.Result{}, nil
	}

	// The resyncs of the daemon cache reconcile the profile while a failed
	// reload waits for its retry, which must not create a job each time.
	if wait := r.reloadRetryDelay(sp, time.Now()); wait > 0 {
		l.Info("Waiting to retry the failed policy reload",
			"generation", reloadGeneration, "policyName", sp.GetPolicyName(), "retryAfter", wait)

		return reconcile.Result{RequeueAfter: wait}, nil
	}

	state, err := r.createPolicyReloadJob(
		ctx, sp.GetPolicyName(), kind, sp.GetUID(), generation, l,
	)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("%w: %w", errCreateReloadJob, err)
	}

	switch state {
	case reloadJobBusy:
		return reconcile.Result{RequeueAfter: reloadJobRetryInterval}, nil
	case reloadJobFailed:
		return r.retryFailedReload(sp, kind, l), nil
	case reloadJobCreated, reloadJobRunning:
		if kind.waitForCompletion {
			return reconcile.Result{RequeueAfter: reloadJobRetryInterval}, nil
		}
	case reloadJobDone:
		r.forgetReloadFailures(client.ObjectKeyFromObject(sp))
	}

	// A foreground deletion removes the node status before the profile, so
	// there is nothing to record the reload in. The label of the job still
	// keeps a retry from creating another one.
	if err := nodeStatus.SetAnnotation(ctx, annotation, reloadGeneration); err != nil &&
		!kerrors.IsNotFound(err) {
		return reconcile.Result{}, fmt.Errorf(
			"recording the %s reload of generation %s: %w", action, reloadGeneration, err,
		)
	}

	return reconcile.Result{}, nil
}

// retryFailedReload counts the failed reload job of the generation of the
// profile and returns when to create a new one. The first failure of a
// generation gets reported, the further ones only get logged, so that a
// reload which keeps failing does not flood the profile with events.
func (r *ReconcileSelinux) retryFailedReload(
	sp selinuxprofileapi.SelinuxProfileObject, kind reloadKind, l logr.Logger,
) reconcile.Result {
	failures, delay := r.recordReloadFailure(sp, time.Now())

	l.Info("Policy reload job failed, retrying",
		"policyName", sp.GetPolicyName(), "failures", failures, "retryAfter", delay)

	if failures == 1 {
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			reasonCannotReloadPolicy,
			kind.eventAction,
			"Policy reload job failed on %s, retrying",
			r.nodeName,
		)
	}

	return reconcile.Result{RequeueAfter: delay}
}

// reloadInstalledPolicy reloads the kernel policy after the installation of a
// new policy generation. On RHEL 9 and OpenShift 4.20+, semodule -i no longer
// reloads the in-memory policy. The policy is installed even if this fails,
// just not reloaded yet, so the reload gets retried: with backoff if the job
// cannot be created or the job of the generation failed, and after
// reloadJobRetryInterval while a reload job of the policy is still running.
func (r *ReconcileSelinux) reloadInstalledPolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	res, err := r.reloadPolicy(ctx, sp, nodeStatus, installReload, l)
	if errors.Is(err, errCreateReloadJob) {
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
	}

	return res, err
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

	l.Info("Checking if policy is removed", "policyName", sp.GetPolicyName())
	polStatus, err := getPolicyStatus(ctx, sp, r.httpc)

	if errors.Is(err, errPolicyNotFound) {
		// The reload is needed even if this profile never triggered one: the
		// reload of any other profile loads the whole policy store, and
		// releases before the reload annotation did not record one.
		//
		// Policy was successfully removed, trigger a reload to update kernel policy
		return r.reloadRemovedPolicy(ctx, sp, nodeStatus, l)
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

	r.countRemoval(sp)
	l.Info("Policy removed")

	return reconcile.Result{}, nil
}

// countRemoval counts the removal of the policy in the metrics, unless it got
// counted since the policy got installed last. It reports whether it counted
// the removal.
func (r *ReconcileSelinux) countRemoval(sp selinuxprofileapi.SelinuxProfileObject) bool {
	counted, ok := r.removalsCounted.Swap(client.ObjectKeyFromObject(sp), sp.GetUID())
	if ok && counted == sp.GetUID() {
		return false
	}

	r.metrics.IncSelinuxProfileDelete()

	return true
}

// reloadRemovedPolicy reloads the kernel policy after the removal of the
// policy, which keeps the removed module loaded until then.
func (r *ReconcileSelinux) reloadRemovedPolicy(
	ctx context.Context,
	sp selinuxprofileapi.SelinuxProfileObject,
	nodeStatus *nodestatus.StatusClient,
	l logr.Logger,
) (reconcile.Result, error) {
	res, err := r.reloadPolicy(ctx, sp, nodeStatus, removeReload, l)
	if errors.Is(err, errCreateReloadJob) {
		// Unlike a running job, a failure to create one may not go away, and
		// it must not keep the profile from being removed.
		l.Error(err, "Failed to create policy reload job after removal")
		r.record.Eventf(
			sp,
			nil,
			util.EventTypeWarning,
			reasonCannotReloadPolicy,
			util.EventActionRemove,
			"Failed to create policy reload job after removal on %s: %s",
			r.nodeName,
			err.Error(),
		)

		res, err = reconcile.Result{}, nil
	}

	// A requeue means that a reload job of another generation still runs. A
	// retried deletion passes here again after the reload, which must not
	// count the removal again.
	if err == nil && res.IsZero() && r.countRemoval(sp) {
		l.Info("Policy removed")
	}

	return res, err
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

	// A requeue returned with an error is ignored by controller-runtime,
	// which retries with backoff instead.
	return reconcile.Result{}, fmt.Errorf("error removing policy file: %w", err)
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
