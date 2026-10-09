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

package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	reconcileTimeout = 1 * time.Minute
	dsWait           = 30 * time.Second

	// nodeFinalizerSuffix is the suffix of the finalizers which the daemon of
	// a node adds to the profiles, see util.GetFinalizerNodeString.
	nodeFinalizerSuffix = "-deleted"
)

var (
	ErrNoOwnerProfile   = errors.New("no owner profile defined for this status")
	ErrUnknownOwnerKind = errors.New("the node status owner is of an unknown kind")
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &StatusReconciler{}
}

// A StatusReconciler monitors node changes and updates the profile status.
type StatusReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
	record util.EventRecorder
	// namespace is the operator namespace, which holds the SPOd DaemonSet.
	namespace string
}

// Name returns the name of the controller.
func (r *StatusReconciler) Name() string {
	return "nodestatus"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *StatusReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return secprofnodestatusapi.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *StatusReconciler) Healthz(*http.Request) error {
	return nil
}

// Security Profiles Operator RBAC permissions to manage SelinuxProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=rawselinuxprofiles/finalizers,verbs=get;update;patch

// Security Profiles Operator RBAC permissions to manage SeccompProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles/finalizers,verbs=get;update;patch

// Security Profiles Operator RBAC permissions to manage AppArmorProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles/finalizers,verbs=get;update;patch

// Security Profiles Operator RBAC permissions to manage Node Statuses
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilenodestatuses,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//
// The SPOd DaemonSet and its pods tell which nodes run the daemon:
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile reconciles a NodeStatus.
func (r *StatusReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	if kind, name, ok := parseProfileRequest(req); ok {
		return r.reconcileProfile(ctx, kind, util.NamespacedName(name, req.Namespace))
	}

	return r.reconcileNodeStatus(ctx, req, nil, r.newClusterView())
}

// clusterView looks up the SPOd DaemonSet, the node names and the nodes which
// run a SPOd pod once per reconcile, so that the aggregation and the cleanup
// of a deleted profile share them.
type clusterView struct {
	r *StatusReconciler

	ds    *appsv1.DaemonSet
	hasDS bool

	nodeNames    []string
	hasNodeNames bool

	spodPods    []v1.Pod
	hasSpodPods bool
}

func (r *StatusReconciler) newClusterView() *clusterView {
	return &clusterView{r: r}
}

// daemonSet returns the SPOd DaemonSet, or nil if it does not exist.
func (v *clusterView) daemonSet(ctx context.Context) (*appsv1.DaemonSet, error) {
	if !v.hasDS {
		ds, err := v.r.getDS(ctx)
		if err != nil && !kerrors.IsNotFound(err) {
			return nil, err
		}

		v.ds, v.hasDS = ds, true
	}

	return v.ds, nil
}

// nodes returns the names of all nodes of the cluster.
func (v *clusterView) nodes(ctx context.Context) ([]string, error) {
	if !v.hasNodeNames {
		names, err := v.r.nodeNames(ctx)
		if err != nil {
			return nil, err
		}

		v.nodeNames = names
		v.hasNodeNames = true
	}

	return v.nodeNames, nil
}

// pods returns the pods of the SPOd DaemonSet, see StatusReconciler.spodPods.
func (v *clusterView) pods(ctx context.Context, spodDS *appsv1.DaemonSet) ([]v1.Pod, error) {
	if !v.hasSpodPods {
		pods, err := v.r.spodPods(ctx, spodDS)
		if err != nil {
			return nil, err
		}

		v.spodPods, v.hasSpodPods = pods, true
	}

	return v.spodPods, nil
}

// spodNodesOf returns the nodes which run a SPOd pod, including terminating
// ones, because their daemon may still run. It returns false if the
// DaemonSet has not settled, so that a node without a pod cannot be told
// apart from a node whose pod is about to be created. Without a DaemonSet, no
// node runs a SPOd pod or gets one, so that is settled.
func (v *clusterView) spodNodesOf(
	ctx context.Context, spodDS *appsv1.DaemonSet,
) (nodes map[string]bool, settled bool, err error) {
	if spodDS == nil {
		return map[string]bool{}, true, nil
	}

	if spodDS.Spec.Selector == nil {
		return nil, false, nil
	}

	pods, err := v.pods(ctx, spodDS)
	if err != nil {
		return nil, false, err
	}

	nodes = make(map[string]bool, len(pods))

	for i := range pods {
		if pods[i].Spec.NodeName != "" {
			nodes[pods[i].Spec.NodeName] = true
		}
	}

	return nodes, daemonSetSettled(spodDS, len(nodes)), nil
}

// reconcileProfile aggregates the node statuses of a profile into the status
// of the profile by reconciling its first node status, and removes the
// finalizers of deleted nodes if the profile is being deleted. The events of
// all node statuses of a profile map to this single request, so a rollout
// over many nodes lists the statuses once per reconcile, not once per event.
func (r *StatusReconciler) reconcileProfile(
	ctx context.Context, kind string, key types.NamespacedName,
) (reconcile.Result, error) {
	list, err := listStatusesForProfile(
		ctx, r.client, key.Namespace, util.KindNameDNSLengthName(kind, key.Name),
	)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot list node statuses of profile: %w", err)
	}

	view := r.newClusterView()

	var statusResult reconcile.Result

	if first := firstOwnedStatus(list, kind, key.Name); first != nil {
		statusResult, err = r.reconcileNodeStatus(
			ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(first)}, list, view,
		)
		if err != nil {
			return statusResult, err
		}
	}

	deletionResult, err := r.reconcileDeletingProfile(ctx, kind, key, view)
	if err != nil {
		return deletionResult, err
	}

	if !statusResult.IsZero() {
		return statusResult, nil
	}

	return deletionResult, nil
}

// reconcileNodeStatus aggregates the node statuses of the profile which owns
// the node status of the request into the status of the profile. The node
// statuses of the profile are listed unless the caller provides them.
func (r *StatusReconciler) reconcileNodeStatus(
	ctx context.Context,
	req reconcile.Request,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
	view *clusterView,
) (reconcile.Result, error) {
	logger := r.log.WithValues("nodeStatus", req.Name, "namespace", req.Namespace)
	logger.V(config.VerboseLevel).Info("Reconciling node status")

	// get the status to be reconciled
	instance := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := r.client.Get(ctx, req.NamespacedName, instance); err != nil {
		// Expected to find a node profile, return an error and requeue
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	prof, err := r.getProfileFromStatus(ctx, instance)
	if err != nil {
		return r.ownerError(instance, err, logger)
	}

	lprof := logger.WithValues(
		"Profile.Name", prof.GetName(),
		"Profile.Namespace", prof.GetNamespace(),
		"Profile.Kind", prof.GetObjectKind().GroupVersionKind(),
	)

	// A status which does not belong to the profile must not seed its state.
	if !r.statusMatchesOwner(instance, prof, logger) {
		return reconcile.Result{}, nil
	}

	// Initialize the status if it hasn't happened already, so that the profile
	// shows a state while the aggregation below waits for the other nodes.
	if prof.GetStatusBase().Status == "" {
		lprof.Info("Initializing Profile status")

		targetStatus := secprofnodestatusapi.ProfileStatePending
		if instance.Status.Status != "" {
			targetStatus = instance.Status.Status
		}

		prof, err = r.reconcileStatus(ctx, prof, aggregation{state: targetStatus}, lprof)
		if err != nil || prof == nil {
			return reconcile.Result{}, err
		}
	}

	if nodeStatusList == nil {
		nodeStatusList, err = listStatusesForProfile(
			ctx,
			r.client,
			instance.Namespace,
			instance.Labels[secprofnodestatusapi.StatusToProfLabel],
		)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("cannot list the node statuses: %w", err)
		}
	}

	return r.aggregateStatuses(ctx, prof, nodeStatusList, view, lprof)
}

// ownerError reports a node status whose owner profile cannot be determined.
// A status without an owner, or with an owner of an unknown kind, cannot be
// reconciled by a retry, so it is only reported. Other errors, like a failed
// lookup of the owner, are retried.
func (r *StatusReconciler) ownerError(
	instance *secprofnodestatusapi.SecurityProfileNodeStatus, err error, logger logr.Logger,
) (reconcile.Result, error) {
	r.record.Eventf(
		instance,
		nil,
		v1.EventTypeWarning,
		"ReconcileError",
		util.EventActionReconcile,
		"%s",
		err.Error(),
	)

	if errors.Is(err, ErrNoOwnerProfile) || errors.Is(err, ErrUnknownOwnerKind) {
		logger.Info("Skipping node status without a known owner, will not requeue", "reason", err)

		return reconcile.Result{}, nil
	}

	return reconcile.Result{}, err
}

// statusMatchesOwner returns true if the profile label of the node status
// matches the owner profile. A mismatch is reported, a retry cannot fix it.
func (r *StatusReconciler) statusMatchesOwner(
	instance *secprofnodestatusapi.SecurityProfileNodeStatus,
	prof profilebaseapi.StatusBaseUser,
	logger logr.Logger,
) bool {
	profLabel := instance.Labels[secprofnodestatusapi.StatusToProfLabel]

	var msg string

	switch {
	case profLabel == "":
		logger.Info("Skipping unlabeled node status, will not requeue")

		msg = "unlabeled node status"
	// The owner reference names the kind of the profile, whose TypeMeta may
	// be empty after a write.
	case util.KindNameDNSLengthName(metav1.GetControllerOf(instance).Kind, prof.GetName()) != profLabel:
		logger.Info("Status doesn't match owner, will not requeue")

		msg = "status doesn't match owner"
	default:
		return true
	}

	r.record.Eventf(
		instance,
		nil,
		v1.EventTypeWarning,
		"ReconcileError",
		util.EventActionReconcile,
		"%s",
		msg,
	)

	return false
}

// aggregateStatuses sets the lowest state of the node statuses as the status
// of the profile, once every node running the SPOd reported one. It removes
// the statuses and finalizers of nodes which are gone or do not run the SPOd
// anymore. While the SPOd pods of some nodes are unavailable, the statuses of
// the other nodes are aggregated, see aggregateAvailableStatuses.
func (r *StatusReconciler) aggregateStatuses(
	ctx context.Context,
	prof profilebaseapi.StatusBaseUser,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
	view *clusterView,
	logger logr.Logger,
) (reconcile.Result, error) {
	spodDS, err := view.daemonSet(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot get the DS: %w", err)
	}

	if spodDS == nil {
		logger.V(config.VerboseLevel).Info(
			"Not updating policy because the SPOd DaemonSet does not exist",
		)

		return reconcile.Result{RequeueAfter: dsWait}, nil
	}

	if !daemonSetIsReady(spodDS) || daemonSetIsUpdating(spodDS) {
		if !daemonSetIsRollingOut(spodDS) {
			return r.aggregateAvailableStatuses(ctx, prof, nodeStatusList, spodDS, view, logger)
		}

		// If the DS is rolling out, don't bother updating the status. This
		// repeats every dsWait for every profile, so it is not worth an info
		// log.
		logger.V(config.VerboseLevel).Info("Not updating policy because the SPOd is not ready")

		return reconcile.Result{RequeueAfter: dsWait}, nil
	}

	// make sure we have all the statuses already
	hasStatuses := len(nodeStatusList.Items)
	wantsStatuses := int(spodDS.Status.DesiredNumberScheduled)

	requeue := reconcile.Result{}

	// Right after a node got deleted, the DaemonSet may still count it. Its
	// status must not count for the profile, and nothing but the requeue
	// reconciles the profile again once the DaemonSet caught up.
	if wantsStatuses >= hasStatuses {
		deleted, err := r.statusesOfDeletedNodes(ctx, nodeStatusList)
		if err != nil {
			return reconcile.Result{}, err
		}

		if len(deleted) > 0 {
			logger.Info("Waiting for the DaemonSet to drop deleted nodes", "nodes", len(deleted))

			return reconcile.Result{RequeueAfter: dsWait}, nil
		}
	}

	if wantsStatuses > hasStatuses {
		logger.Info("Not updating policy: not all statuses are ready",
			"has", hasStatuses, "wants", wantsStatuses)

		// The status of a node usually follows soon and triggers the next
		// reconcile. Check again later anyway, a SPOd pod which becomes
		// unavailable before its daemon created the status triggers nothing.
		return reconcile.Result{RequeueAfter: dsWait}, nil
	} else if wantsStatuses < hasStatuses {
		// this happens when nodes are removed from the cluster or no longer
		// run the SPOd, for example because of a new taint
		logger.Info("Removing extra statuses", "has", hasStatuses, "wants", wantsStatuses)

		removed, err := r.removeStaleStatuses(ctx, prof, spodDS, nodeStatusList, view, logger)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("cannot remove extra statuses: %w", err)
		}

		if removed {
			return reconcile.Result{RequeueAfter: time.Second}, nil
		}

		// The stale statuses cannot be identified yet, for example while
		// the DaemonSet rolls out. Aggregate the existing ones and check again
		// later instead of requeuing every second.
		logger.Info("No stale status identified, aggregating the existing statuses")

		requeue = reconcile.Result{RequeueAfter: dsWait}
	}

	if err := r.removeDeletedNodeFinalizers(ctx, prof, view, logger); err != nil {
		return reconcile.Result{}, err
	}

	agg := lowestState(nodeStatusList.Items)

	logger.V(config.VerboseLevel).Info("Setting the status to", "Status", agg.state)

	_, err = r.reconcileStatus(ctx, prof, agg, logger)

	return requeue, err
}

// aggregateAvailableStatuses aggregates the statuses of the nodes which run
// an available SPOd pod, while the pods of other nodes are unavailable, for
// example because their node is not ready. Waiting for every pod would keep
// all profiles from getting ready until the last node recovered. The rules:
//
//   - The DaemonSet runs its current pods on every node, a rollout is waited
//     for, see daemonSetIsRollingOut.
//   - Every node with an available SPOd pod has to report a status, otherwise
//     the profile waits for it, like it waits for all nodes otherwise.
//   - The statuses of the nodes without an available SPOd pod do not count,
//     their daemon cannot update them. The Ready condition names these nodes.
//   - The statuses and finalizers of deleted nodes and of nodes which do not
//     run a SPOd pod are removed as usual.
//
// The profile is checked again after dsWait, because a recovering pod does
// not change any status.
func (r *StatusReconciler) aggregateAvailableStatuses(
	ctx context.Context,
	prof profilebaseapi.StatusBaseUser,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
	spodDS *appsv1.DaemonSet,
	view *clusterView,
	logger logr.Logger,
) (reconcile.Result, error) {
	requeue := reconcile.Result{RequeueAfter: dsWait}

	pods, err := view.pods(ctx, spodDS)
	if err != nil {
		return reconcile.Result{}, err
	}

	available := availableSpodNodes(spodDS, pods, time.Now())
	if len(available) == 0 {
		logger.V(config.VerboseLevel).Info("Not updating policy because no SPOd pod is available")

		return requeue, nil
	}

	removed, err := r.removeStaleStatuses(ctx, prof, spodDS, nodeStatusList, view, logger)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot remove extra statuses: %w", err)
	}

	if removed {
		return reconcile.Result{RequeueAfter: time.Second}, nil
	}

	if err := r.removeDeletedNodeFinalizers(ctx, prof, view, logger); err != nil {
		return reconcile.Result{}, err
	}

	var counted []secprofnodestatusapi.SecurityProfileNodeStatus

	reported := map[string]bool{}

	for i := range nodeStatusList.Items {
		if node := nodeStatusList.Items[i].Spec.NodeName; available[node] {
			counted = append(counted, nodeStatusList.Items[i])
			reported[node] = true
		}
	}

	if len(reported) < len(available) {
		logger.Info(
			"Not updating policy: not all nodes with an available SPOd pod reported a status",
			"has",
			len(reported),
			"wants",
			len(available),
		)

		return requeue, nil
	}

	agg := lowestState(counted)

	unavailable := map[string]bool{}

	for i := range pods {
		if node := pods[i].Spec.NodeName; node != "" && !available[node] {
			unavailable[node] = true
		}
	}

	agg.unavailableNodes = slices.Sorted(maps.Keys(unavailable))

	// The DaemonSet may want pods which do not exist yet, whose nodes are
	// unknown.
	agg.unnamedUnavailable = max(0,
		int(spodDS.Status.DesiredNumberScheduled)-len(available)-len(agg.unavailableNodes))

	logger.V(config.VerboseLevel).Info("Setting the status to", "Status", agg.state,
		"unavailableNodes", len(agg.unavailableNodes)+agg.unnamedUnavailable)

	_, err = r.reconcileStatus(ctx, prof, agg, logger)

	return requeue, err
}

// removeDeletedNodeFinalizers removes the finalizers of nodes which do not
// exist anymore. They are taken from the profile rather than from the
// statuses, because a status can be gone already, for example after a failed
// attempt to remove the finalizer or when the garbage collector deleted it.
func (r *StatusReconciler) removeDeletedNodeFinalizers(
	ctx context.Context, prof client.Object, view *clusterView, logger logr.Logger,
) error {
	nodeNames, err := view.nodes(ctx)
	if err != nil {
		return err
	}

	return r.removeNodeFinalizers(ctx, prof, deletedNodeFinalizers(prof, nodeNames), logger)
}

// aggregation is the aggregated state of the node statuses of a profile.
type aggregation struct {
	state secprofnodestatusapi.ProfileState

	// failedNodes are the nodes whose profile is in the Error state, if
	// known.
	failedNodes []string

	// unavailableNodes are the nodes whose SPOd pod is not available, so
	// that the state leaves them out. unnamedUnavailable counts further
	// such nodes whose names are unknown.
	unavailableNodes   []string
	unnamedUnavailable int
}

// unavailableMessage returns the part of the message of the Ready condition
// which names the nodes the state leaves out, if any.
func (a *aggregation) unavailableMessage() string {
	if len(a.unavailableNodes)+a.unnamedUnavailable == 0 {
		return ""
	}

	return "the SPOd pod is not available on " + a.unavailableNodeList() + ", which the state leaves out"
}

// unavailableNodeList returns the nodes whose SPOd pod is not available, for
// a message.
func (a *aggregation) unavailableNodeList() string {
	nodes := nodeList(a.unavailableNodes, a.unnamedUnavailable)
	if len(a.unavailableNodes) > 0 {
		nodes = "nodes " + nodes
	}

	return nodes
}

// lowestState aggregates the node statuses into their lowest state and the
// nodes whose profile is in the Error state.
func lowestState(statuses []secprofnodestatusapi.SecurityProfileNodeStatus) aggregation {
	agg := aggregation{state: secprofnodestatusapi.LowestState}

	for i := range statuses {
		status := &statuses[i]
		agg.state = secprofnodestatusapi.LowerOfTwoStates(agg.state, status.Status.Status)

		if status.Status.Status == secprofnodestatusapi.ProfileStateError {
			agg.failedNodes = append(agg.failedNodes, status.Spec.NodeName)
		}
	}

	slices.Sort(agg.failedNodes)

	return agg
}

// removeStaleStatuses removes the statuses and finalizers of nodes which have
// been deleted or no longer run a SPOd pod. It returns true if any status was
// removed. The finalizer gets removed before the status, because the status is
// what makes this path find the node again if removing the finalizer fails.
func (r *StatusReconciler) removeStaleStatuses(
	ctx context.Context,
	prof client.Object,
	spodDS *appsv1.DaemonSet,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
	view *clusterView,
	logger logr.Logger,
) (bool, error) {
	stale, err := r.statusesOfDeletedNodes(ctx, nodeStatusList)
	if err != nil {
		return false, err
	}

	if len(stale) == 0 {
		stale, err = statusesOfUnscheduledNodes(ctx, spodDS, nodeStatusList, view, logger)
		if err != nil {
			return false, err
		}
	}

	if len(stale) == 0 {
		return false, nil
	}

	// The legacy finalizer of a stale node stays as long as another node
	// shares it, see staleNodeFinalizers.
	nodeNames, err := view.nodes(ctx)
	if err != nil {
		return false, err
	}

	staleNodes := make([]string, 0, len(stale))
	for _, status := range stale {
		staleNodes = append(staleNodes, status.Spec.NodeName)
	}

	for _, status := range stale {
		node := status.Spec.NodeName
		logger.Info("Removing node status and finalizer from profile", "node", node)

		if err := r.removeNodeFinalizers(
			ctx, prof, staleNodeFinalizers([]string{node}, staleNodes, nodeNames), logger,
		); err != nil {
			return false, err
		}

		if err := client.IgnoreNotFound(r.client.Delete(ctx, status)); err != nil {
			return false, fmt.Errorf("cannot delete node status: %w", err)
		}
	}

	return true, nil
}

// removeNodeFinalizers removes the provided node finalizers from the profile.
func (r *StatusReconciler) removeNodeFinalizers(
	ctx context.Context,
	prof client.Object,
	finalizers []string,
	logger logr.Logger,
) error {
	present := slices.DeleteFunc(slices.Clone(finalizers), func(finalizer string) bool {
		return !controllerutil.ContainsFinalizer(prof, finalizer)
	})
	if len(present) == 0 {
		return nil
	}

	logger.Info("Removing node finalizers from profile", "finalizers", present)

	// A retry reads the profile from the API server, the cache may keep
	// returning the version which conflicted.
	if err := util.RetryWithFreshReads(ctx, r.client, r.reader, func(c client.Client) error {
		return client.IgnoreNotFound(util.RemoveFinalizers(ctx, c, prof, present...))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("cannot remove finalizers %v from profile: %w", present, err)
	}

	return nil
}

// isNodeFinalizer returns true if the finalizer is one the daemon of a node
// adds to a profile, see util.GetFinalizerNodeString. Node names cannot
// contain a slash, while qualified finalizers like the one of partial
// profiles do.
func isNodeFinalizer(finalizer string) bool {
	return strings.HasSuffix(finalizer, nodeFinalizerSuffix) && !strings.Contains(finalizer, "/")
}

// nodeNames returns the names of all nodes of the cluster. The nodes are
// listed as metadata only, which shares the informer of the other controllers
// instead of caching the full node objects a second time.
func (r *StatusReconciler) nodeNames(ctx context.Context) ([]string, error) {
	nodes := &metav1.PartialObjectMetadataList{}
	nodes.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("NodeList"))

	if err := r.client.List(ctx, nodes); err != nil {
		return nil, fmt.Errorf("cannot get node list: %w", err)
	}

	names := make([]string, 0, len(nodes.Items))
	for i := range nodes.Items {
		names = append(names, nodes.Items[i].Name)
	}

	return names, nil
}

// nodeFinalizers returns the finalizers which the daemon of the node may
// have added to a profile: the current one and, for a long node name, the
// truncated one of earlier releases.
func nodeFinalizers(nodeName string) []string {
	finalizers := []string{util.GetFinalizerNodeString(nodeName)}
	if legacy := util.GetLegacyFinalizerNodeString(nodeName); legacy != "" {
		finalizers = append(finalizers, legacy)
	}

	return finalizers
}

// staleNodeFinalizers returns the finalizers to remove for the nodes, which
// are among the stale ones: their current finalizers, and their legacy ones
// unless a node which is not stale shares them. The legacy finalizer of
// earlier releases is shared by all nodes whose long names start with the same
// prefix, and the daemon of a remaining node removes it along with its own.
func staleNodeFinalizers(nodes, staleNodes, nodeNames []string) []string {
	shared := map[string]bool{}

	for _, name := range nodeNames {
		if slices.Contains(staleNodes, name) {
			continue
		}

		if legacy := util.GetLegacyFinalizerNodeString(name); legacy != "" {
			shared[legacy] = true
		}
	}

	var finalizers []string

	for _, name := range nodes {
		finalizers = append(finalizers, util.GetFinalizerNodeString(name))

		if legacy := util.GetLegacyFinalizerNodeString(name); legacy != "" && !shared[legacy] {
			finalizers = append(finalizers, legacy)
		}
	}

	return finalizers
}

// deletedNodeFinalizers returns the node finalizers of the profile which do
// not belong to any of the provided node names. The legacy finalizer of an
// existing node is never returned, as other nodes may still rely on it, see
// staleNodeFinalizers.
func deletedNodeFinalizers(prof client.Object, nodeNames []string) []string {
	existing := make(map[string]bool, len(nodeNames))
	for _, name := range nodeNames {
		for _, finalizer := range nodeFinalizers(name) {
			existing[finalizer] = true
		}
	}

	var stale []string

	for _, finalizer := range prof.GetFinalizers() {
		if isNodeFinalizer(finalizer) && !existing[finalizer] {
			stale = append(stale, finalizer)
		}
	}

	return stale
}

// spodPods returns the pods of the SPOd DaemonSet, none if it has no
// selector.
func (r *StatusReconciler) spodPods(
	ctx context.Context, spodDS *appsv1.DaemonSet,
) ([]v1.Pod, error) {
	if spodDS.Spec.Selector == nil {
		return nil, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(spodDS.Spec.Selector)
	if err != nil {
		return nil, fmt.Errorf("cannot parse SPOd selector: %w", err)
	}

	pods := &v1.PodList{}
	if err := r.client.List(ctx, pods,
		client.InNamespace(spodDS.Namespace),
		client.MatchingLabelsSelector{Selector: selector},
	); err != nil {
		return nil, fmt.Errorf("cannot list SPOd pods: %w", err)
	}

	return pods.Items, nil
}

// availableSpodNodes returns the nodes which run an available SPOd pod, like
// the DaemonSet controller counts them: the pod is not being deleted and has
// been ready for the minReadySeconds of the DaemonSet.
func availableSpodNodes(spodDS *appsv1.DaemonSet, pods []v1.Pod, now time.Time) map[string]bool {
	minReady := time.Duration(spodDS.Spec.MinReadySeconds) * time.Second
	nodes := map[string]bool{}

	for i := range pods {
		pod := &pods[i]
		if pod.Spec.NodeName == "" || !pod.DeletionTimestamp.IsZero() {
			continue
		}

		for _, cond := range pod.Status.Conditions {
			if cond.Type == v1.PodReady && cond.Status == v1.ConditionTrue &&
				(minReady == 0 || !cond.LastTransitionTime.Add(minReady).After(now)) {
				nodes[pod.Spec.NodeName] = true
			}
		}
	}

	return nodes
}

// statusesOfUnscheduledNodes returns the statuses of live nodes which do not
// run a SPOd pod anymore. The daemon on such a node can never remove its
// finalizer, so deleting the profile would hang forever. A node counts as not
// running the SPOd only if the DaemonSet status proves that every node it
// schedules to runs exactly one up to date pod, and no pod runs anywhere else.
// Then a node without a pod, including a terminating one, is not scheduled.
func statusesOfUnscheduledNodes(
	ctx context.Context,
	spodDS *appsv1.DaemonSet,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
	view *clusterView,
	logger logr.Logger,
) ([]*secprofnodestatusapi.SecurityProfileNodeStatus, error) {
	spodNodes, settled, err := view.spodNodesOf(ctx, spodDS)
	if err != nil {
		return nil, err
	}

	if !settled {
		logger.Info("Not removing statuses of live nodes while the SPOd is not settled")

		return nil, nil
	}

	var stale []*secprofnodestatusapi.SecurityProfileNodeStatus

	for i := range nodeStatusList.Items {
		if !spodNodes[nodeStatusList.Items[i].Spec.NodeName] {
			stale = append(stale, &nodeStatusList.Items[i])
		}
	}

	return stale, nil
}

// daemonSetSettled returns true if the status of the DaemonSet is current and
// shows that the pods run on exactly the nodes it schedules to: every
// scheduled node runs an up to date pod, no pod runs on a node it does not
// schedule to, and the pod list has one node per scheduled node.
func daemonSetSettled(ds *appsv1.DaemonSet, podNodes int) bool {
	status := &ds.Status

	return status.ObservedGeneration == ds.Generation &&
		status.NumberMisscheduled == 0 &&
		status.CurrentNumberScheduled == status.DesiredNumberScheduled &&
		status.UpdatedNumberScheduled == status.DesiredNumberScheduled &&
		podNodes == int(status.DesiredNumberScheduled)
}

// statusesOfDeletedNodes returns the statuses of nodes which have been
// deleted.
func (r *StatusReconciler) statusesOfDeletedNodes(
	ctx context.Context,
	nodeStatusList *secprofnodestatusapi.SecurityProfileNodeStatusList,
) ([]*secprofnodestatusapi.SecurityProfileNodeStatus, error) {
	var stale []*secprofnodestatusapi.SecurityProfileNodeStatus

	for i := range nodeStatusList.Items {
		nodeName := nodeStatusList.Items[i].Spec.NodeName
		node := &metav1.PartialObjectMetadata{}
		node.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("Node"))

		if err := r.client.Get(ctx, types.NamespacedName{Name: nodeName}, node); err != nil {
			// Only a NotFound proves the node is gone. Treating a Conflict as
			// deletion would strip the finalizer of a live node's status.
			if !kerrors.IsNotFound(err) {
				return nil, fmt.Errorf("cannot get node: %w", err)
			}

			stale = append(stale, &nodeStatusList.Items[i])
		}
	}

	return stale, nil
}

// reconcileDeletingProfile removes the node finalizers of a profile which is
// being deleted and whose daemon cannot remove them anymore, because the node
// is gone or does not run a SPOd pod. Such a profile may have no status left
// to reconcile, for example after a foreground deletion, so it is reconciled
// on its own.
func (r *StatusReconciler) reconcileDeletingProfile(
	ctx context.Context, kind string, key types.NamespacedName, view *clusterView,
) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", key.Name, "namespace", key.Namespace, "kind", kind)

	prof, err := newProfile(kind)
	if err != nil {
		return reconcile.Result{}, err
	}

	if err := r.client.Get(ctx, key, prof); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	if prof.GetDeletionTimestamp().IsZero() {
		return reconcile.Result{}, nil
	}

	// The finalizers of deleted nodes go first, they do not depend on the
	// SPOd DaemonSet.
	if err := r.removeDeletedNodeFinalizers(ctx, prof, view, logger); err != nil {
		return reconcile.Result{}, err
	}

	nodeNames, err := view.nodes(ctx)
	if err != nil {
		return reconcile.Result{}, err
	}

	spodDS, err := view.daemonSet(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cannot get the DS: %w", err)
	}

	spodNodes, settled, err := view.spodNodesOf(ctx, spodDS)
	if err != nil {
		return reconcile.Result{}, err
	}

	if settled {
		var unscheduled []string

		for _, name := range nodeNames {
			if !spodNodes[name] {
				unscheduled = append(unscheduled, name)
			}
		}

		if err := r.removeNodeFinalizers(
			ctx, prof, staleNodeFinalizers(unscheduled, unscheduled, nodeNames), logger,
		); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Check again once the DaemonSet settled. The daemons of the remaining
	// nodes remove their finalizers on their own.
	if !settled && slices.ContainsFunc(prof.GetFinalizers(), isNodeFinalizer) {
		return reconcile.Result{RequeueAfter: dsWait}, nil
	}

	return reconcile.Result{}, nil
}

// profileRequestSeparator separates the kind and the name of a profile in a
// profile request. Object names cannot contain it, so a profile request never
// collides with the request of a node status.
const profileRequestSeparator = "/"

// profileRequest returns the request which reconciles the profile of the
// provided kind and name itself, rather than one of its node statuses.
func profileRequest(kind, namespace, name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{
		Namespace: namespace,
		Name:      kind + profileRequestSeparator + name,
	}}
}

// parseProfileRequest returns the kind and name of the profile if the request
// is a profile request.
func parseProfileRequest(req reconcile.Request) (kind, name string, ok bool) {
	return strings.Cut(req.Name, profileRequestSeparator)
}

func (r *StatusReconciler) getDS(ctx context.Context) (*appsv1.DaemonSet, error) {
	spodDS := appsv1.DaemonSet{}
	spodName := util.NamespacedName(config.SPOdName, r.namespace)

	if err := r.client.Get(ctx, spodName, &spodDS); err != nil {
		return nil, fmt.Errorf("cannot Get DS: %w", err)
	}

	return &spodDS, nil
}

func (r *StatusReconciler) getProfileFromStatus(
	ctx context.Context,
	s *secprofnodestatusapi.SecurityProfileNodeStatus,
) (profilebaseapi.StatusBaseUser, error) {
	ctrl := metav1.GetControllerOf(s)
	if ctrl == nil {
		return nil, fmt.Errorf("getting owner profile: %w", ErrNoOwnerProfile)
	}

	key := types.NamespacedName{
		Name:      ctrl.Name,
		Namespace: s.GetNamespace(),
	}

	prof, err := newProfile(ctrl.Kind)
	if err != nil {
		return nil, err
	}

	if err := r.client.Get(ctx, key, prof); err != nil {
		return nil, fmt.Errorf("getting owner profile: %s/%s: %w", s.GetNamespace(), ctrl.Name, err)
	}

	return prof, nil
}

// newProfile returns an empty profile of the provided kind.
func newProfile(kind string) (profilebaseapi.StatusBaseUser, error) {
	switch kind {
	case "SeccompProfile":
		return &seccompprofileapi.SeccompProfile{}, nil
	case "SelinuxProfile":
		return &selinuxprofileapi.SelinuxProfile{}, nil
	case "RawSelinuxProfile":
		return &selinuxprofileapi.RawSelinuxProfile{}, nil
	case "AppArmorProfile":
		return &apparmorapi.AppArmorProfile{}, nil
	default:
		return nil, fmt.Errorf("getting owner profile: %w", ErrUnknownOwnerKind)
	}
}

// newProfileList returns an empty list of profiles of the provided kind.
func newProfileList(kind string) (client.ObjectList, error) {
	switch kind {
	case "SeccompProfile":
		return &seccompprofileapi.SeccompProfileList{}, nil
	case "SelinuxProfile":
		return &selinuxprofileapi.SelinuxProfileList{}, nil
	case "RawSelinuxProfile":
		return &selinuxprofileapi.RawSelinuxProfileList{}, nil
	case "AppArmorProfile":
		return &apparmorapi.AppArmorProfileList{}, nil
	default:
		return nil, fmt.Errorf("listing profiles: %w", ErrUnknownOwnerKind)
	}
}

// profilesOf returns the profiles of a list returned by newProfileList.
func profilesOf(list client.ObjectList) ([]client.Object, error) {
	var profiles []client.Object

	if err := apimeta.EachListItem(list, func(obj runtime.Object) error {
		if prof, ok := obj.(client.Object); ok {
			profiles = append(profiles, prof)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("reading the profile list: %w", err)
	}

	return profiles, nil
}

// reconcileStatus sets the aggregated state on the profile and returns the
// profile as stored afterwards, or nil if the profile is gone. The profile is
// expected to come from the cache, so an unchanged status costs no request to
// the API server. The profile is only read from the API server after a
// conflict, which means that the cache is outdated.
func (r *StatusReconciler) reconcileStatus(
	ctx context.Context,
	prof profilebaseapi.StatusBaseUser,
	agg aggregation,
	l logr.Logger,
) (profilebaseapi.StatusBaseUser, error) {
	key := client.ObjectKeyFromObject(prof)
	current := prof

	var stored profilebaseapi.StatusBaseUser

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if current == nil {
			current = prof.DeepCopyToStatusBaseIf()
			if err := r.reader.Get(ctx, key, current); err != nil {
				return err
			}
		}

		var err error

		stored, err = r.updateProfileStatus(ctx, current, agg, l)
		current = nil

		return err
	})

	// A profile which is gone in the meantime has no status to update.
	return stored, client.IgnoreNotFound(err)
}

// maxNodesInMessage limits the nodes the Ready condition of a profile names,
// the SecurityProfileNodeStatus objects list all of them.
const maxNodesInMessage = 5

// errorConditionMessage returns the message of the Ready condition of a
// profile which failed to install on the provided nodes.
func errorConditionMessage(failedNodes []string) string {
	const hint = "the status.message of the SecurityProfileNodeStatus objects with the " +
		secprofnodestatusapi.StatusToProfLabel + " label of the profile tells why"

	if len(failedNodes) == 0 {
		return "profile failed to install on one or more nodes, " + hint
	}

	return fmt.Sprintf("profile failed to install on nodes %s, %s", nodeList(failedNodes, 0), hint)
}

// nodeList returns the first nodes of the list, followed by the number of
// the others. unnamed is the number of further nodes whose names are unknown.
func nodeList(nodes []string, unnamed int) string {
	shown := min(len(nodes), maxNodesInMessage)
	list := strings.Join(nodes[:shown], ", ")

	more := len(nodes) - shown + unnamed

	switch {
	case more <= 0:
		return list
	case shown == 0 && more == 1:
		return "1 node"
	case shown == 0:
		return fmt.Sprintf("%d nodes", more)
	default:
		return fmt.Sprintf("%s and %d more", list, more)
	}
}

// updateProfileStatus writes the status of the profile if it changed, and
// returns the profile as stored afterwards.
func (r *StatusReconciler) updateProfileStatus(
	ctx context.Context,
	prof profilebaseapi.StatusBaseUser,
	agg aggregation,
	l logr.Logger,
) (profilebaseapi.StatusBaseUser, error) {
	pCopy := prof.DeepCopyToStatusBaseIf()

	// We always set this status
	pCopy.SetImplementationStatus()

	outStatus := pCopy.GetStatusBase()

	var condition metav1.Condition

	// The reasons of the conditions are part of the API, only the messages
	// may change.
	switch agg.state {
	case secprofnodestatusapi.ProfileStatePending, "":
		outStatus.Status = secprofnodestatusapi.ProfileStatePending
		condition = common.Creating()
	case secprofnodestatusapi.ProfileStateInProgress:
		outStatus.Status = secprofnodestatusapi.ProfileStateInProgress
		condition = common.Creating()
	case secprofnodestatusapi.ProfileStateInstalled:
		outStatus.Status = secprofnodestatusapi.ProfileStateInstalled
		condition = common.Available()

		// The profile may be missing on the nodes the state leaves out.
		if agg.unavailableMessage() != "" {
			condition.Reason = string(profilebaseapi.ReasonInstalledOnAvailableNodes)
		}
	case secprofnodestatusapi.ProfileStateTerminating:
		outStatus.Status = secprofnodestatusapi.ProfileStateTerminating
		condition = common.Deleting()
	case secprofnodestatusapi.ProfileStateError:
		outStatus.Status = secprofnodestatusapi.ProfileStateError
		condition = common.Unavailable(errorConditionMessage(agg.failedNodes))
	case secprofnodestatusapi.ProfileStatePartial:
		outStatus.Status = secprofnodestatusapi.ProfileStatePartial
		condition = common.Unavailable(
			"profile is a partial profile of a profile recording, marked by the " +
				profilebaseapi.ProfilePartialLabel + " label, which is not merged yet",
		)
	case secprofnodestatusapi.ProfileStateDisabled:
		outStatus.Status = secprofnodestatusapi.ProfileStateDisabled
		condition = common.Unavailable(
			"profile is disabled by spec.state Disabled, which a profile recording " +
				"with disableProfileAfterRecording sets on the recorded profile",
		)
	}

	if condition.Type != "" {
		if msg := agg.unavailableMessage(); msg != "" {
			if condition.Message != "" {
				msg = condition.Message + "; " + msg
			}

			condition.Message = msg
		}

		outStatus.SetConditionForGeneration(&condition, pCopy.GetGeneration())
	}

	if !profileStatusChanged(prof, pCopy) {
		return prof, nil
	}

	l.V(config.VerboseLevel).Info("Updating status")

	if updateErr := r.client.Status().Update(ctx, pCopy); updateErr != nil {
		return nil, fmt.Errorf("updating policy status: %w", updateErr)
	}

	r.reportUnavailableNodes(prof, pCopy, agg)

	return pCopy, nil
}

// reportUnavailableNodes records a warning event on a profile which got
// installed while the SPOd pods of some nodes are not available, because pods
// using the profile fail on these nodes. The status only gets written if it
// changed, and the event only gets recorded if the Ready condition changed
// with it, so it repeats only when the named nodes change, not on every
// requeue.
func (r *StatusReconciler) reportUnavailableNodes(
	old, updated profilebaseapi.StatusBaseUser, agg aggregation,
) {
	cond := updated.GetStatusBase().GetReadyCondition()
	if cond.Reason != string(profilebaseapi.ReasonInstalledOnAvailableNodes) {
		return
	}

	if oldCond := old.GetStatusBase().GetReadyCondition(); oldCond.Reason == cond.Reason &&
		oldCond.Message == cond.Message {
		return
	}

	r.record.Eventf(
		updated,
		nil,
		v1.EventTypeWarning,
		string(profilebaseapi.ReasonInstalledOnAvailableNodes),
		util.EventActionReconcile,
		"Profile is only installed on the nodes with an available SPOd pod, it may be missing on %s, "+
			"where pods using it fail to start until the SPOd pod recovers",
		agg.unavailableNodeList(),
	)
}

func profileStatusChanged(current, desired profilebaseapi.StatusBaseUser) bool {
	switch typedCurrent := current.(type) {
	case *seccompprofileapi.SeccompProfile:
		typedDesired, ok := desired.(*seccompprofileapi.SeccompProfile)

		return !ok || !reflect.DeepEqual(typedCurrent.Status, typedDesired.Status)
	case *selinuxprofileapi.SelinuxProfile:
		typedDesired, ok := desired.(*selinuxprofileapi.SelinuxProfile)

		return !ok || !reflect.DeepEqual(typedCurrent.Status, typedDesired.Status)
	case *selinuxprofileapi.RawSelinuxProfile:
		typedDesired, ok := desired.(*selinuxprofileapi.RawSelinuxProfile)

		return !ok || !reflect.DeepEqual(typedCurrent.Status, typedDesired.Status)
	case *apparmorapi.AppArmorProfile:
		typedDesired, ok := desired.(*apparmorapi.AppArmorProfile)

		return !ok || !reflect.DeepEqual(typedCurrent.Status, typedDesired.Status)
	default:
		return true
	}
}

func daemonSetIsReady(ds *appsv1.DaemonSet) bool {
	return ds.Status.DesiredNumberScheduled > 0 &&
		ds.Status.DesiredNumberScheduled == ds.Status.NumberAvailable
}

func daemonSetIsUpdating(ds *appsv1.DaemonSet) bool {
	return ds.Status.UpdatedNumberScheduled > 0 &&
		(ds.Status.UpdatedNumberScheduled < ds.Status.DesiredNumberScheduled || ds.Status.NumberUnavailable > 0)
}

// daemonSetIsRollingOut returns true if the pods of the DaemonSet are about
// to change: it schedules no pod, its controller has not observed its spec
// yet, or not every node it schedules to runs the current pod template.
// Unlike daemonSetIsUpdating, a pod which is current but not available, like
// on a node which is not ready, does not count.
func daemonSetIsRollingOut(ds *appsv1.DaemonSet) bool {
	status := &ds.Status

	return status.DesiredNumberScheduled == 0 ||
		status.ObservedGeneration != ds.Generation ||
		status.UpdatedNumberScheduled < status.DesiredNumberScheduled
}

// listStatusesForProfile lists the node statuses whose profile label has the
// provided value. They are looked up with the index of the label, instead of
// filtering the statuses of all profiles.
func listStatusesForProfile(
	ctx context.Context, c client.Client, namespace string, labelVal string,
) (*secprofnodestatusapi.SecurityProfileNodeStatusList, error) {
	statusList := secprofnodestatusapi.SecurityProfileNodeStatusList{}
	if err := c.List(ctx, &statusList,
		client.InNamespace(namespace),
		client.MatchingFields{statusProfileIndex: labelVal},
	); err != nil {
		return nil, fmt.Errorf("listing statuses: %w", err)
	}

	return &statusList, nil
}
