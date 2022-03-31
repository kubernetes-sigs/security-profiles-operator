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

package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	rcommonv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	pbv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	reconcileTimeout = 1 * time.Minute
	dsWait           = 30 * time.Second
)

var (
	ErrNoOwnerProfile  = errors.New("no owner profile defined for this status")
	ErrUnkownOwnerKind = errors.New("the node status owner is of an unknown kind")
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &StatusReconciler{}
}

// A StatusReconciler monitors node changes and updates the profile status.
type StatusReconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
}

// Name returns the name of the controller.
func (r *StatusReconciler) Name() string {
	return "nodestatus"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *StatusReconciler) SchemeBuilder() *scheme.Builder {
	return statusv1alpha1.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *StatusReconciler) Healthz(*http.Request) error {
	return nil
}

func NewStatusReconciler(cli client.Client, log logr.Logger, record event.Recorder) *StatusReconciler {
	return &StatusReconciler{
		client: cli,
		log:    log,
		record: record,
	}
}

// Security Profiles Operator RBAC permissions to manage SelinuxProfile
// nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=delete;get;update;patch

// Security Profiles Operator RBAC permissions to manage SeccompProfile
// nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=delete;get;update;patch

// Security Profiles Operator RBAC permissions to manage Node Statuses
// nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch

// Reconcile reconciles a NodeStatus.
func (r *StatusReconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("nodeStatus", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling node status")

	// get the status to be reconciled
	instance := &statusv1alpha1.SecurityProfileNodeStatus{}
	if err := r.client.Get(ctx, req.NamespacedName, instance); err != nil {
		// Expected to find a node profile, return an error and requeue
		return reconcile.Result{}, util.IgnoreNotFound(err)
	}

	prof, getProfErr := r.getProfileFromStatus(ctx, instance)
	if getProfErr != nil {
		return reconcile.Result{}, getProfErr
	}

	lprof := logger.WithValues(
		"Profile.Name", prof.GetName(),
		"Profile.Namespace", prof.GetNamespace(),
		"Profile.Kind", prof.GetObjectKind().GroupVersionKind(),
	)

	// Initialize status if it hasn't happened already
	if prof.GetStatusBase().Status == "" {
		lprof.Info("Initializing Profile status")

		targetStatus := statusv1alpha1.ProfileStatePending
		if instance.Status != "" {
			targetStatus = instance.Status
		}
		return r.reconcileStatus(ctx, prof, targetStatus, lprof)
	}

	// get all the other statuses
	profLabel := instance.Labels[statusv1alpha1.StatusToProfLabel]
	if profLabel == "" {
		return reconcile.Result{}, errors.New("unlabeled node status")
	}

	if util.KindBasedDNSLengthName(prof) != instance.Labels[statusv1alpha1.StatusToProfLabel] {
		return reconcile.Result{}, errors.New("status doesn't match owner")
	}

	nodeStatusList, err := listStatusesForProfile(ctx, r.client, profLabel)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot list the node statuses: %w", err)
	}

	// get the DS
	spodDS, err := r.getDS(ctx, config.GetOperatorNamespace(), lprof)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot get the DS: %w", err)
	}

	if !daemonSetIsReady(spodDS) || daemonSetIsUpdating(spodDS) {
		// If the DS is not ready or updating, don't bother updating the status
		logger.Info("Not updating policy because the SPOd is not ready")
		return reconcile.Result{RequeueAfter: dsWait}, nil
	}

	// make sure we have all the statuses already
	hasStatuses := len(nodeStatusList.Items)
	wantsStatuses := spodDS.Status.DesiredNumberScheduled
	if wantsStatuses != int32(hasStatuses) {
		logger.Info("Not updating policy: not all statuses are ready",
			"has", hasStatuses, "wants", wantsStatuses)
		// Don't reconcile again, let's just wait for another update
		return reconcile.Result{}, nil
	}

	lowestCommonState := statusv1alpha1.LowestState
	for i := range nodeStatusList.Items {
		lowestCommonState = statusv1alpha1.LowerOfTwoStates(lowestCommonState, nodeStatusList.Items[i].Status)
	}
	logger.Info("Setting the status to", "Status", lowestCommonState)

	return r.reconcileStatus(ctx, prof, lowestCommonState, lprof)
}

func (r *StatusReconciler) getDS(ctx context.Context, namespace string, l logr.Logger) (*appsv1.DaemonSet, error) {
	dsSelect := labels.NewSelector()
	spodDSFilter, err := labels.NewRequirement("spod", selection.Exists, []string{})
	if err != nil {
		return nil, fmt.Errorf("cannot create DS list label: %w", err)
	}
	dsSelect.Add(*spodDSFilter)
	dsListOpts := client.ListOptions{
		LabelSelector: dsSelect,
		Namespace:     namespace,
	}

	spodDSList := appsv1.DaemonSetList{}
	if err := r.client.List(ctx, &spodDSList, &dsListOpts); err != nil {
		return nil, fmt.Errorf("cannot list DS: %w", err)
	}

	if len(spodDSList.Items) != 1 {
		retErr := errors.New("did not find exactly one DS")
		l.Error(retErr, "Expected to find 1 DS", "len(dsList.Items)", len(spodDSList.Items))
		return nil, fmt.Errorf("listing DS: %w", retErr)
	}

	return &spodDSList.Items[0], nil
}

func (r *StatusReconciler) getProfileFromStatus(
	ctx context.Context,
	s *statusv1alpha1.SecurityProfileNodeStatus,
) (pbv1alpha1.StatusBaseUser, error) {
	ctrl := metav1.GetControllerOf(s)
	if ctrl == nil {
		return nil, fmt.Errorf("getting owner profile: %w", ErrNoOwnerProfile)
	}

	key := types.NamespacedName{
		Name:      ctrl.Name,
		Namespace: s.GetNamespace(),
	}
	var prof pbv1alpha1.StatusBaseUser
	switch ctrl.Kind {
	case "SeccompProfile":
		prof = &seccompprofileapi.SeccompProfile{}
	case "SelinuxProfile":
		prof = &selxv1alpha2.SelinuxProfile{}
	default:
		return nil, fmt.Errorf("getting owner profile: %w", ErrUnkownOwnerKind)
	}
	if err := r.client.Get(ctx, key, prof); err != nil {
		return nil, fmt.Errorf("getting owner profile: %s/%s: %w", s.GetNamespace(), ctrl.Name, err)
	}
	return prof, nil
}

func (r *StatusReconciler) reconcileStatus(
	ctx context.Context,
	prof pbv1alpha1.StatusBaseUser,
	state statusv1alpha1.ProfileState,
	l logr.Logger,
) (reconcile.Result, error) {
	pCopy := prof.DeepCopyToStatusBaseIf()

	// We always set this status
	pCopy.SetImplementationStatus()

	outStatus := pCopy.GetStatusBase()
	switch state {
	case statusv1alpha1.ProfileStatePending, "":
		outStatus.Status = statusv1alpha1.ProfileStatePending
		outStatus.SetConditions(rcommonv1.Creating())
	case statusv1alpha1.ProfileStateInProgress:
		outStatus.SetConditions(rcommonv1.Creating())
		outStatus.Status = statusv1alpha1.ProfileStateInProgress
	case statusv1alpha1.ProfileStateInstalled:
		outStatus.Status = statusv1alpha1.ProfileStateInstalled
		outStatus.SetConditions(rcommonv1.Available())
	case statusv1alpha1.ProfileStateTerminating:
		outStatus.Status = statusv1alpha1.ProfileStateTerminating
		outStatus.SetConditions(rcommonv1.Deleting())
	case statusv1alpha1.ProfileStateError:
		outStatus.Status = statusv1alpha1.ProfileStateError
		outStatus.SetConditions(rcommonv1.Unavailable())
	}

	l.Info("Updating status")
	if updateErr := r.client.Status().Update(ctx, pCopy); updateErr != nil {
		return reconcile.Result{}, fmt.Errorf("updating policy status: %w", updateErr)
	}

	return reconcile.Result{}, nil
}

func daemonSetIsReady(ds *appsv1.DaemonSet) bool {
	return ds.Status.DesiredNumberScheduled > 0 && ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable
}

func daemonSetIsUpdating(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled > 0 &&
		(ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled || ds.Status.NumberUnavailable > 0)
}

func listStatusesForProfile(
	ctx context.Context, c client.Client, labelVal string,
) (*statusv1alpha1.SecurityProfileNodeStatusList, error) {
	statusList := statusv1alpha1.SecurityProfileNodeStatusList{}
	allStatusesForProf := client.MatchingLabels{
		statusv1alpha1.StatusToProfLabel: labelVal,
	}

	if err := c.List(ctx, &statusList, allStatusesForProf); err != nil {
		return nil, fmt.Errorf("listing statuses: %w", err)
	}

	return &statusList, nil
}
