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

package spod

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute
	// errorStatusTimeout bounds the status update which reports a failed
	// reconciliation.
	errorStatusTimeout = 10 * time.Second
	// conflictRequeueDelay is the delay before a reconciliation which lost a
	// conflict runs again, which gives the cache time to catch up.
	conflictRequeueDelay = time.Second

	reasonCannotCreateSPOD           string = "CannotCreateSPOD"
	reasonCannotUpdateSPOD           string = "CannotUpdateSPOD"
	reasonCannotMountCustomTemplates string = "CannotMountCustomTemplates"
	reasonInvalidKubeletDirLabel     string = "InvalidKubeletDirLabel"

	reasonCannotApplyAdmissionPolicies string = "CannotApplyAdmissionPolicies"
	reasonWeakenedBindingWebhook       string = "WeakenedBindingWebhook"

	// legacyAppArmorAnnotation got set on the DaemonSet by previous versions.
	// It never had an effect, because it is the removed seccomp annotation and
	// annotations on the DaemonSet do not apply to its pods. It gets removed
	// from existing DaemonSets.
	legacyAppArmorAnnotation = "container.seccomp.security.alpha.kubernetes.io/security-profiles-operator"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &ReconcileSPOd{}
}

// blank assignment to verify that ReconcileSPOd implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSPOd{}

// ReconcileSPOd reconciles the SPOd DaemonSet object.
type ReconcileSPOd struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	// clientReader reads object directly from api-server, this is useful when
	// the cache is not ready (e.g. when listing the cluster nodes).
	clientReader client.Reader
	scheme       *runtime.Scheme
	baseSPOd     *appsv1.DaemonSet
	record       util.EventRecorder
	log          logr.Logger
	namespace    string
	// caInjectType is the certificate provider of the cluster, detected
	// once in Setup.
	caInjectType bindata.CAInjectType

	// skipAdmissionPolicies is set in Setup when the cluster does not serve
	// the ValidatingAdmissionPolicy API, so that the reconciler does not look
	// the kinds up again on every run.
	skipAdmissionPolicies bool

	// watchesCertManager is set in Setup when the controller watches the
	// cert-manager resources of the operator, which requires the cluster to
	// serve the cert-manager API.
	watchesCertManager bool

	// kubeletDirMu guards invalidKubeletDirLabels, which maps the nodes with
	// an invalid kubelet directory label to the reported label value.
	kubeletDirMu            sync.Mutex
	invalidKubeletDirLabels map[string]string

	// env holds the features which the environment of the operator enables.
	env envFlags
}

// Name returns the name of the controller.
func (r *ReconcileSPOd) Name() string {
	return "spod-config"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReconcileSPOd) SchemeBuilder() runtime.SchemeBuilder {
	return spodapi.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *ReconcileSPOd) Healthz(*http.Request) error {
	return nil
}

// Security Profiles Operator RBAC permissions to manage its own configuration
//nolint:lll // required for kubebuilder
//
// Used for event generation. The leader election of controller-runtime still
// records its events through the core API:
// +kubebuilder:rbac:groups=core,resources=events,verbs=create
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
//
// Operand, which lives in the operator namespace. The manager cache for these
// kinds is restricted to that namespace by the manager command.
// +kubebuilder:rbac:groups="",namespace="security-profiles-operator",resources=services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=deployments;daemonsets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,namespace="security-profiles-operator",resources=issuers;certificates,verbs=get;list;watch;create;update;patch
//
// The webhook deployment gets a pod disruption budget:
// +kubebuilder:rbac:groups=policy,namespace="security-profiles-operator",resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch
//
// Webhook configurations are cluster scoped. Create cannot be restricted by
// name, but everything else is limited to the operator owned configurations.
// The manager caches these kinds by name, so list and watch carry the name
// as field selector, which the API server authorizes like a get.
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations;validatingwebhookconfigurations,verbs=create
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,resourceNames=spo-mutating-webhook-configuration,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,resourceNames=spo-validating-webhook-configuration,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/finalizers,verbs=get;update;patch
// Helpers:
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update
//
// Needed for default profiles, and to delete the profiles which the allowed
// syscalls of the SPOD reject:
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch;delete
//
// Needed for the ServiceMonitor
// +kubebuilder:rbac:groups=monitoring.coreos.com,namespace="security-profiles-operator",resources=servicemonitors,verbs=get;list;watch;create;update;patch
//
// OpenShift (This is ignored in other distros):
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resourceNames=restricted-v2,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators,verbs=get
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch
//
// Needed to detect which runtime is active and custom kubelet directories
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//
// Needed to detect the proper selinux image and the log volume of the JSON
// enricher. The manager caches the ConfigMap by name like the webhook
// configurations:
// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=security-profiles-operator-profile,verbs=get;list;watch
//
// Needed to authenticate and authorize metrics requests
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
//
// Needed for the admission policies, see bindata.AdmissionPolicies. They are
// cached by name like the webhook configurations.
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,verbs=create
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,resourceNames=spo-recording-profiles,verbs=get;list;watch;update

// Reconcile reads that state of the cluster for a SPOD object and makes changes based on the state read
// and what is in the `ConfigMap.Spec`.
func (r *ReconcileSPOd) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)
	// Fetch the ConfigMap instance
	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	if err := r.client.Get(ctx, req.NamespacedName, spod); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("getting spod configuration: %w", err)
	}

	if spod.Status.State == "" {
		return reconcile.Result{}, r.handleInitialStatus(ctx, spod, logger)
	}

	if err := r.reconcileSPOD(ctx, spod, logger); err != nil {
		// A conflict only means that the cache is behind, which the next
		// reconciliation resolves, so it is neither reported nor logged as
		// an error.
		if errors.IsConflict(err) {
			logger.V(config.VerboseLevel).Info("Retrying after a conflict", "reason", err)

			return reconcile.Result{RequeueAfter: conflictRequeueDelay}, nil
		}

		r.handleErrorStatus(ctx, spod, logger, err)

		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

// operands are the objects rendered for a SPOD.
type operands struct {
	spod                 *appsv1.DaemonSet
	kubeletDirs          []string
	webhook              *bindata.Webhook
	metricsService       *corev1.Service
	serviceMonitor       *monitoringv1.ServiceMonitor
	certManagerResources *bindata.CertManagerResources
}

// renderOperands renders the operands of the SPOD. It returns false if the
// operator deployment, whose image the operands use, does not exist.
func (r *ReconcileSPOd) renderOperands(
	ctx context.Context, spod *spodapi.SecurityProfilesOperatorDaemon,
) (*operands, bool, error) {
	deploymentKey := types.NamespacedName{
		Name:      config.OperatorName,
		Namespace: r.namespace,
	}
	foundDeployment := &appsv1.Deployment{}

	if err := r.client.Get(ctx, deploymentKey, foundDeployment); err != nil {
		if errors.IsNotFound(err) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("get operator deployment: %w", err)
	}
	// We use the same target image for the deamonset as which we have right
	// now running.
	image := foundDeployment.Spec.Template.Spec.Containers[0].Image
	pullPolicy := foundDeployment.Spec.Template.Spec.Containers[0].ImagePullPolicy

	configuredSPOd, err := r.getConfiguredSPOd(ctx, spod, image, pullPolicy, r.caInjectType)
	if err != nil {
		return nil, false, fmt.Errorf("get configured SPOD: %w", err)
	}

	kubeletDirs, err := r.nodeKubeletDirs(ctx, spod)
	if err != nil {
		return nil, false, fmt.Errorf("get node kubelet directories: %w", err)
	}

	// The metrics service is owned by the SPOD, so that it gets restored if
	// it gets deleted.
	metricsService := bindata.GetMetricsService(r.namespace, r.caInjectType)
	if err := controllerutil.SetControllerReference(spod, metricsService, r.scheme); err != nil {
		return nil, false, fmt.Errorf("setting metrics service controller reference: %w", err)
	}

	ops := &operands{
		spod:           configuredSPOd,
		kubeletDirs:    kubeletDirs,
		webhook:        r.getConfiguredWebook(spod, image, pullPolicy, r.caInjectType),
		metricsService: metricsService,
		serviceMonitor: bindata.ServiceMonitor(
			r.namespace, r.caInjectType, ptr.Deref(spod.Spec.EnableInsecureMetricsAccess, false),
		),
	}

	if r.caInjectType == bindata.CAInjectTypeCertManager {
		ops.certManagerResources = bindata.GetCertManagerResources(r.namespace)
	}

	return ops, true, nil
}

// reconcileSPOD creates or updates the operands of the SPOD and reports the
// rollout in its status.
func (r *ReconcileSPOd) reconcileSPOD(
	ctx context.Context, spod *spodapi.SecurityProfilesOperatorDaemon, logger logr.Logger,
) error {
	ops, found, err := r.renderOperands(ctx, spod)
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	r.applyAdmissionPolicies(ctx, spod, ops.webhook)

	spodKey := types.NamespacedName{Name: spod.GetName(), Namespace: r.namespace}
	foundSPOd := &appsv1.DaemonSet{}

	if err := r.client.Get(ctx, spodKey, foundSPOd); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("getting spod DaemonSet: %w", err)
		}

		addKubeletDirVolumes(&ops.spod.Spec.Template.Spec, ops.kubeletDirs)

		if err := r.handleCreate(ctx, spod, ops); err != nil {
			r.record.Eventf(
				spod, nil, util.EventTypeWarning, reasonCannotCreateSPOD,
				util.EventActionReconcile, "%s", err.Error(),
			)

			return err
		}

		return r.handleCreatingStatus(ctx, spod, logger)
	}

	dirs, spodUpdate := kubeletDirsToMount(ops.spod, foundSPOd, ops.kubeletDirs)
	addKubeletDirVolumes(&ops.spod.Spec.Template.Spec, dirs)

	if err := r.ensureMetricsService(ctx, spod, ops.metricsService); err != nil {
		return err
	}

	if err := r.ensureCertManagerResources(ctx, ops.certManagerResources); err != nil {
		return err
	}

	var hookUpdate bool
	if !ptr.Deref(spod.Spec.Webhook.StaticConfig, false) {
		hookUpdate, err = ops.webhook.NeedsUpdate(ctx, r.client)
		if err != nil {
			return fmt.Errorf("determining if webhook needs update: %w", err)
		}
	}

	if spodUpdate || hookUpdate {
		r.log.Info("Updating spod", "spodUpdate", spodUpdate, "hookUpdate", hookUpdate)

		if err := r.handleUpdate(ctx, spod, foundSPOd, ops); err != nil {
			// A conflict is expected when the cache is behind, and the next
			// reconciliation resolves it without anyone having to act.
			if !errors.IsConflict(err) {
				r.record.Eventf(
					spod, nil, util.EventTypeWarning, reasonCannotUpdateSPOD,
					util.EventActionUpdate, "%s", err.Error(),
				)
			}

			return err
		}

		return r.handleUpdatingStatus(ctx, spod, logger)
	}

	if daemonSetRolledOut(foundSPOd) {
		condready := spod.Status.GetReadyCondition()
		// Don't pollute the logs. Let's only update when needed.
		if condready.Status != metav1.ConditionTrue {
			return r.handleRunningStatus(ctx, spod, logger)
		}
	} else if spod.Status.State == spodapi.SPODStateRunning ||
		spod.Status.State == spodapi.SPODStateError {
		// Pods of the SPOd became unavailable, for example because they
		// crash or a node got added which cannot run them, or the last
		// reconciliation failed and the rollout continues now.
		return r.handleUpdatingStatus(ctx, spod, logger)
	}

	// Spec changes which touch neither the DaemonSet nor the webhook, like
	// the allowed syscalls, are reconciled as well, so the status reports
	// that the current generation got observed. The status is only written if
	// the generation changed.
	return r.updateStatus(
		ctx,
		spod,
		logger,
		"Updating the observed generation of the SPOD instance",
		func(*spodapi.SPODStatus) {},
	)
}

// daemonSetRolledOut returns true if the DaemonSet controller observed the
// current spec and every scheduled pod is up to date and available.
func daemonSetRolledOut(ds *appsv1.DaemonSet) bool {
	status := &ds.Status

	return status.ObservedGeneration >= ds.Generation &&
		status.UpdatedNumberScheduled == status.DesiredNumberScheduled &&
		status.NumberAvailable == status.DesiredNumberScheduled &&
		status.NumberReady == status.DesiredNumberScheduled
}

// ensureMetricsService creates the metrics service if it is missing, for
// example because it got deleted, and makes the SPOD its owner, so that its
// deletion is noticed.
func (r *ReconcileSPOd) ensureMetricsService(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	metricsService *corev1.Service,
) error {
	found := &corev1.Service{}

	err := r.client.Get(ctx, client.ObjectKeyFromObject(metricsService), found)
	if errors.IsNotFound(err) {
		r.log.Info("Creating missing metrics service")

		if err := r.client.Create(ctx, metricsService.DeepCopy()); err != nil &&
			!errors.IsAlreadyExists(err) {
			return fmt.Errorf("creating metrics service: %w", err)
		}

		return nil
	}

	if err != nil {
		return fmt.Errorf("getting metrics service: %w", err)
	}

	if !metav1.IsControlledBy(found, spod) {
		if err := r.client.Patch(ctx, metricsService.DeepCopy(), client.Merge); err != nil {
			return fmt.Errorf("updating metrics service owner: %w", err)
		}
	}

	return nil
}

// ensureCertManagerResources creates the cert-manager resources which are
// missing, for example because they got deleted. They are not owned by the
// SPOD, so that deleting the SPOD does not remove the certificates of the
// webhook, which keeps running for the webhook configurations left behind.
// The resources are only checked if the controller watches them, because the
// cache can only read them then.
func (r *ReconcileSPOd) ensureCertManagerResources(
	ctx context.Context, resources *bindata.CertManagerResources,
) error {
	if resources == nil || !r.watchesCertManager {
		return nil
	}

	missing, err := resources.Missing(ctx, r.client)
	if err != nil {
		return fmt.Errorf("checking cert manager resources: %w", err)
	}

	if !missing {
		return nil
	}

	r.log.Info("Creating missing cert manager resources")

	if err := resources.Update(ctx, r.client); err != nil {
		return fmt.Errorf("updating cert manager resources: %w", err)
	}

	return nil
}

// applyAdmissionPolicies applies the admission policies of the operator,
// which for example restrict the use of the recording profiles to the
// namespaces selected by the recording webhook. The policies are watched, so
// changed or deleted ones are restored. Failures are reported but do not block
// the reconciliation, and the policies get applied again on the next one.
func (r *ReconcileSPOd) applyAdmissionPolicies(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	webhook *bindata.Webhook,
) {
	if r.skipAdmissionPolicies {
		return
	}

	policies := bindata.GetAdmissionPolicies(webhook.RecordingNamespaceSelector())

	if err := policies.Apply(ctx, r.client); err != nil {
		if bindata.IsNotFound(err) {
			r.log.V(config.VerboseLevel).Info(
				"ValidatingAdmissionPolicy API not available, skipping the admission policies",
			)

			return
		}

		r.log.Error(err, "Cannot apply the admission policies")
		r.record.Eventf(
			spod,
			nil,
			util.EventTypeWarning,
			reasonCannotApplyAdmissionPolicies,
			util.EventActionReconcile,
			"%s",
			err.Error(),
		)
	}
}

// updateStatus applies set to a copy of the SPOD status, records the
// observed generation and writes the status if it changed.
func (r *ReconcileSPOd) updateStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
	message string,
	set func(*spodapi.SPODStatus),
) error {
	sCopy := spod.DeepCopy()
	set(&sCopy.Status)
	sCopy.Status.SetObservedGeneration(spod.Generation)

	if apiequality.Semantic.DeepEqual(spod.Status, sCopy.Status) {
		return nil
	}

	l.Info(message)

	if err := r.client.Status().Update(ctx, sCopy); err != nil {
		return fmt.Errorf("updating spod status to %s: %w", sCopy.Status.State, err)
	}

	return nil
}

func (r *ReconcileSPOd) handleInitialStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) error {
	return r.updateStatus(ctx, spod, l, "Adding an initial status to the SPOD instance",
		func(s *spodapi.SPODStatus) { s.StatePending() })
}

func (r *ReconcileSPOd) handleCreatingStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) error {
	return r.updateStatus(ctx, spod, l, "Adding 'Creating' status to the SPOD instance",
		func(s *spodapi.SPODStatus) { s.StateCreating() })
}

func (r *ReconcileSPOd) handleUpdatingStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) error {
	return r.updateStatus(ctx, spod, l, "Adding 'Updating' status to the SPOD instance",
		func(s *spodapi.SPODStatus) { s.StateUpdating() })
}

func (r *ReconcileSPOd) handleRunningStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) error {
	return r.updateStatus(ctx, spod, l, "Adding 'Running' status to the SPOD instance",
		func(s *spodapi.SPODStatus) { s.StateRunning() })
}

// handleErrorStatus reports a failed reconciliation in the status of the
// SPOD. It is best effort: the reconciliation error is what gets returned and
// retried, so a failed status update is only logged. The reconciliation
// context may have expired, so the update gets its own deadline.
func (r *ReconcileSPOd) handleErrorStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
	reconcileErr error,
) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), errorStatusTimeout)
	defer cancel()

	if err := r.updateStatus(ctx, spod, l, "Adding 'Error' status to the SPOD instance",
		func(s *spodapi.SPODStatus) { s.StateError(reconcileErr.Error()) },
	); err != nil {
		l.Error(err, "Cannot report the reconciliation error in the SPOD status")
	}
}

func (r *ReconcileSPOd) defaultProfiles(
	cfg *spodapi.SecurityProfilesOperatorDaemon,
) (defaultProfiles []*seccompprofileapi.SeccompProfile) {
	if ptr.Deref(cfg.Spec.Enricher.EnableLogEnricher, false) {
		defaultProfiles = append(defaultProfiles, bindata.DefaultLogEnricherProfile())
	}

	return defaultProfiles
}

func (r *ReconcileSPOd) handleCreate(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	ops *operands,
) error {
	if ops.certManagerResources != nil {
		r.log.Info("Deploying cert manager resources")

		if err := ops.certManagerResources.Create(ctx, r.client); err != nil {
			return fmt.Errorf("creating cert manager resources: %w", err)
		}
	}

	if !ptr.Deref(cfg.Spec.Webhook.StaticConfig, false) {
		r.log.Info("Deploying operator webhook")
		r.warnWeakenedBinding(cfg, ops.webhook)

		if err := ops.webhook.Create(ctx, r.client); err != nil {
			return fmt.Errorf("creating webhook: %w", err)
		}
	}

	r.log.Info("Creating operator resources")

	if err := controllerutil.SetControllerReference(cfg, ops.spod, r.scheme); err != nil {
		return fmt.Errorf("setting spod controller reference: %w", err)
	}

	r.log.Info("Deploying operator daemonset")

	if err := r.client.Create(ctx, ops.spod); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("creating operator DaemonSet: %w", err)
	}

	r.log.Info("Deploying operator default profiles")

	for _, profile := range r.defaultProfiles(cfg) {
		if err := r.client.Create(ctx, profile); err != nil {
			if errors.IsAlreadyExists(err) {
				continue
			}

			return fmt.Errorf("creating operator default profile %s: %w", profile.Name, err)
		}
	}

	r.log.Info("Deploying metrics service")

	if err := r.client.Create(ctx, ops.metricsService); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("creating metrics service: %w", err)
	}

	r.log.Info("Deploying operator service monitor")

	if err := r.client.Create(
		ctx, ops.serviceMonitor,
	); err != nil {
		switch {
		case bindata.IsNotFound(err):
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		case errors.IsAlreadyExists(err):
			r.log.Info("Service monitor already exist, skipping")
		default:
			return fmt.Errorf("creating service monitor: %w", err)
		}
	}

	return nil
}

// handleUpdate updates the operands, starting with the pod template of the
// found SPOd DaemonSet, which gets replaced by the configured one.
func (r *ReconcileSPOd) handleUpdate(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	foundSPOd *appsv1.DaemonSet,
	ops *operands,
) error {
	if ops.certManagerResources != nil {
		r.log.Info("Updating cert manager resources")

		if err := ops.certManagerResources.Update(ctx, r.client); err != nil {
			return fmt.Errorf("updating cert manager resources: %w", err)
		}
	}

	if !ptr.Deref(cfg.Spec.Webhook.StaticConfig, false) {
		r.log.Info("Updating operator webhook")
		r.warnWeakenedBinding(cfg, ops.webhook)

		if err := ops.webhook.Update(ctx, r.client); err != nil {
			return fmt.Errorf("updating webhook: %w", err)
		}
	}

	r.log.Info("Updating operator daemonset")

	updatedSPOd := foundSPOd.DeepCopy()
	updatedSPOd.Spec.Template = ops.spod.Spec.Template
	delete(updatedSPOd.Annotations, legacyAppArmorAnnotation)

	// The patch is the difference between the found and the updated
	// DaemonSet, so fields which got cleared in the configuration, like the
	// affinity, are removed by it. Unlike an update it does not carry the
	// resource version, so a cache which is behind the API server does not
	// cause a conflict. The operator owns the whole pod template, so nobody
	// else's change can get lost.
	if err := r.client.Patch(ctx, updatedSPOd, client.MergeFrom(foundSPOd)); err != nil {
		return fmt.Errorf("updating operator DaemonSet: %w", err)
	}

	r.log.Info("Updating operator default profiles")

	for _, profile := range r.defaultProfiles(cfg) {
		pKey := types.NamespacedName{Name: profile.GetName()}
		foundProfile := &seccompprofileapi.SeccompProfile{}

		var err error
		if err = r.client.Get(ctx, pKey, foundProfile); err == nil {
			updatedProfile := foundProfile.DeepCopy()
			updatedProfile.Spec = *profile.Spec.DeepCopy()

			if updateErr := r.client.Update(ctx, updatedProfile); updateErr != nil {
				return fmt.Errorf(
					"updating operator default profile %s: %w",
					profile.Name,
					updateErr,
				)
			}

			continue
		}

		if errors.IsNotFound(err) {
			// Handle new default profile
			if createErr := r.client.Create(ctx, profile); createErr != nil &&
				!errors.IsAlreadyExists(createErr) {
				return fmt.Errorf(
					"creating operator default profile %s: %w",
					profile.Name,
					createErr,
				)
			}

			continue
		}

		return fmt.Errorf("getting operator default profile %s: %w", profile.Name, err)
	}

	r.log.Info("Updating metrics service")

	if err := patchOrCreate(ctx, r.client, ops.metricsService); err != nil {
		return fmt.Errorf("updating metrics service: %w", err)
	}

	r.log.Info("Updating operator service monitor")

	if err := patchOrCreate(ctx, r.client, ops.serviceMonitor); err != nil {
		if bindata.IsNotFound(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else {
			return fmt.Errorf("updating service monitor: %w", err)
		}
	}

	return nil
}

// warnWeakenedBinding reports the webhook options of the SPOD which weaken the
// enforcement of the profile bindings. They are valid and get applied, so the
// report is a warning when the webhook configuration gets written.
func (r *ReconcileSPOd) warnWeakenedBinding(
	spod *spodapi.SecurityProfilesOperatorDaemon, webhook *bindata.Webhook,
) {
	for _, warning := range webhook.BindingWarnings() {
		r.log.Info("Webhook options weaken the profile bindings", "warning", warning)
		r.record.Eventf(
			spod, nil, util.EventTypeWarning, reasonWeakenedBindingWebhook,
			util.EventActionReconcile, "%s", warning,
		)
	}
}

// patchOrCreate merge patches the object and creates it if it does not exist.
func patchOrCreate(ctx context.Context, c client.Client, obj client.Object) error {
	err := c.Patch(ctx, obj, client.Merge)
	if errors.IsNotFound(err) {
		return c.Create(ctx, obj)
	}

	return err
}

// baseContainer returns a deep copy of the base SPOd container with the given
// index. Copying is required because the base SPOd is long lived and shared
// across reconciliations, while its containers carry pointer fields (most
// importantly SecurityContext) which the rendering below mutates. Handing out
// the base container directly would persist per-reconciliation configuration
// into the base and make it impossible to ever revert it.
func (r *ReconcileSPOd) baseContainer(id int) corev1.Container {
	return *r.baseSPOd.Spec.Template.Spec.Containers[id].DeepCopy()
}

// baseInitContainer returns a deep copy of the base SPOd init container with
// the given index. See baseContainer for why the copy is required.
func (r *ReconcileSPOd) baseInitContainer(id int) corev1.Container {
	return *r.baseSPOd.Spec.Template.Spec.InitContainers[id].DeepCopy()
}

// getConfiguredSPOd gets a fully configured SPOd instance from a desired
// configuration and the reference base SPOd.
func (r *ReconcileSPOd) getConfiguredSPOd(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	image string,
	pullPolicy corev1.PullPolicy,
	caInjectType bindata.CAInjectType,
) (*appsv1.DaemonSet, error) {
	newSPOd := r.baseSPOd.DeepCopy()

	newSPOd.SetName(cfg.GetName())
	newSPOd.SetNamespace(r.namespace)
	templateSpec := &newSPOd.Spec.Template.Spec

	templateSpec.InitContainers = []corev1.Container{
		r.baseInitContainer(bindata.InitContainerIDNonRootenabler),
	}
	// Set Images
	// Base workload
	templateSpec.Containers = []corev1.Container{
		r.baseContainer(bindata.ContainerIDDaemon),
	}
	templateSpec.Containers[bindata.ContainerIDDaemon].Image = image

	// Non root enabler
	templateSpec.InitContainers[bindata.InitContainerIDNonRootenabler].Image = image

	// SPOD Name
	for envid := range templateSpec.Containers[bindata.ContainerIDDaemon].Env {
		env := &templateSpec.Containers[bindata.ContainerIDDaemon].Env[envid]
		if env.Name == config.SPOdNameEnvKey {
			env.Value = cfg.GetName()

			break
		}
	}

	// Overwrite the SPOD's default resource requirements
	if cfg.Spec.DaemonResourceRequirements != nil {
		templateSpec.Containers[bindata.ContainerIDDaemon].Resources = *cfg.Spec.DaemonResourceRequirements
	}

	if err := r.configureSelinux(cfg, templateSpec, caInjectType); err != nil {
		return nil, err
	}

	if err := r.configureRecording(ctx, cfg, templateSpec, image); err != nil {
		return nil, err
	}

	configureAppArmor(cfg, templateSpec)

	// Enable memory optimization for spod controller
	if ptr.Deref(cfg.Spec.EnableMemoryOptimization, false) {
		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-mem-optim=true")
	}

	if r.isInsecureMetricsEnabled(cfg) {
		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-insecure-metrics-access=true")
	}

	configureContainerDefaults(cfg, templateSpec, pullPolicy)

	templateSpec.Tolerations = cfg.Spec.Scheduling.Tolerations
	templateSpec.Affinity = cfg.Spec.Scheduling.Affinity
	templateSpec.ImagePullSecrets = cfg.Spec.ImagePullSecrets
	templateSpec.PriorityClassName = cfg.Spec.Scheduling.PriorityClassName

	pruneUnmountedVolumes(templateSpec)

	return newSPOd, nil
}

// configureSelinux adds the SELinux containers and parameters if SELinux
// support is enabled, which is the default on OpenShift.
func (r *ReconcileSPOd) configureSelinux(
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	templateSpec *corev1.PodSpec,
	caInjectType bindata.CAInjectType,
) error {
	enableSelinux := (cfg.Spec.Selinux.Enable != nil && *cfg.Spec.Selinux.Enable) ||
		// enable SELinux support per default in OpenShift
		(cfg.Spec.Selinux.Enable == nil && caInjectType == bindata.CAInjectTypeOpenShift)

	if !enableSelinux {
		if cfg.Spec.Selinux.CustomTemplatesConfigMap != "" {
			r.log.Info(
				"customTemplatesConfigMap is set but SELinux is disabled, the field will be ignored",
			)
		}

		return nil
	}

	templateSpec.InitContainers = append(
		templateSpec.InitContainers,
		r.baseInitContainer(bindata.InitContainerIDSelinuxSharedPoliciesCopier),
	)
	templateSpec.Containers = append(
		templateSpec.Containers,
		r.baseContainer(bindata.ContainerIDSelinuxd))

	daemon := &templateSpec.Containers[bindata.ContainerIDDaemon]
	daemon.VolumeMounts = append(daemon.VolumeMounts, corev1.VolumeMount{
		Name:      "host-varlibselinux-volume",
		MountPath: bindata.SelinuxModuleStorePath,
		ReadOnly:  true,
	})

	enableRawSelinux := ptr.Deref(cfg.Spec.Selinux.EnableRawSelinuxProfiles, true)
	daemon.Args = append(daemon.Args,
		"--with-selinux=true",
		fmt.Sprintf("--with-raw-selinux=%t", enableRawSelinux),
	)

	if err := addSelinuxCustomTemplatesVolume(cfg, templateSpec); err != nil {
		r.record.Eventf(
			cfg,
			nil,
			util.EventTypeWarning,
			reasonCannotMountCustomTemplates,
			util.EventActionReconcile,
			"%s",
			err.Error(),
		)

		return fmt.Errorf("unable to mount custom SELinux templates: %w", err)
	}

	return nil
}

// configureRecording adds the containers of the enabled recorders and
// enrichers and enables the profile recording controller of the daemon if
// any of them is enabled.
func (r *ReconcileSPOd) configureRecording(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	templateSpec *corev1.PodSpec,
	image string,
) error {
	// Custom host proc volume
	useCustomHostProc := cfg.Spec.HostProcVolumePath != bindata.DefaultHostProcPath &&
		cfg.Spec.HostProcVolumePath != ""
	volume, mount := bindata.CustomHostProcVolume(cfg.Spec.HostProcVolumePath)

	// Disable profile recording controller by default
	enableRecording := false

	if r.isLogEnricherEnabled(cfg) || r.isBpfRecorderEnabled(cfg) || r.isJsonEnricherEnabled(cfg) {
		if useCustomHostProc {
			templateSpec.Volumes = append(templateSpec.Volumes, volume)
		}

		// HostPID is required for the log-enricher and bpf recorder
		// and is used to access cgroup files to map Process IDs to Pod IDs
		templateSpec.HostPID = true

		// Enable profile recording controller which is disabled by default
		enableRecording = true
	}

	templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
		templateSpec.Containers[bindata.ContainerIDDaemon].Args,
		fmt.Sprintf("--with-recording=%t", enableRecording))

	// addContainer adds the base container with the provided ID and passes
	// the env var to the daemon, as the profile recorder is otherwise disabled.
	addContainer := func(id int, envKey string, configure func(*corev1.Container)) {
		ctr := r.baseContainer(id)
		ctr.Image = image

		if useCustomHostProc {
			ctr.VolumeMounts = append(ctr.VolumeMounts, mount)
		}

		configure(&ctr)

		templateSpec.Containers = append(templateSpec.Containers, ctr)
		r.addEnvVar(templateSpec, envKey)
	}

	if r.isLogEnricherEnabled(cfg) {
		addContainer(bindata.ContainerIDLogEnricher, config.EnableLogEnricherEnvKey,
			func(ctr *corev1.Container) { r.configureLogEnricher(cfg, ctr) })
	}

	if r.isBpfRecorderEnabled(cfg) {
		addContainer(bindata.ContainerIDBpfRecorder, config.EnableBpfRecorderEnvKey,
			func(ctr *corev1.Container) {
				// Configure the apparmor profile for bpf-recorder when apparmor is enabled.
				// The recorder runs privileged then like the daemon, as its
				// profile does not cover loading the BPF programs yet, see
				// configureAppArmor.
				if ptr.Deref(cfg.Spec.EnableAppArmor, false) {
					// The API server rejects privileged containers which
					// disallow privilege escalation.
					ctr.SecurityContext.AllowPrivilegeEscalation = new(true)
					ctr.SecurityContext.Privileged = new(true)
					ctr.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: new(config.BpfRecorderApparmorProfileName),
					}
				}
			})
	}

	if r.isJsonEnricherEnabled(cfg) {
		var volumeErr error

		addContainer(bindata.ContainerIDJsonEnricher, config.EnableJsonEnricherEnvKey,
			func(ctr *corev1.Container) {
				volumeErr = r.addJsonEnricherLogVolume(ctx, templateSpec, ctr)
				r.configureJsonEnricher(cfg, ctr)
			})

		if volumeErr != nil {
			return volumeErr
		}
	}

	return nil
}

// addJsonEnricherLogVolume adds the optional log volume of the json enricher.
// Its configuration is read from the cached ConfigMap during each
// reconciliation, and a change of the ConfigMap triggers one, so ConfigMap
// updates apply without an operator restart. A ConfigMap
// which does not configure the volume is fine, while a failed read is an
// error: rendering the template without the volume would roll the SPOd, and
// the next successful read would roll it back.
func (r *ReconcileSPOd) addJsonEnricherLogVolume(
	ctx context.Context,
	templateSpec *corev1.PodSpec,
	ctr *corev1.Container,
) error {
	logVolumeSource, logVolumeMountPath, err := r.getJsonEnricherVolume(ctx, r.client)
	if err != nil {
		if isJsonEnricherVolumeNotConfigured(err) {
			return nil
		}

		return fmt.Errorf("getting the JSON enricher log volume: %w", err)
	}

	logVolume, logMount := bindata.CustomLogVolume(logVolumeMountPath, logVolumeSource)

	// Replace an existing volume or mount instead of skipping it, so that
	// ConfigMap changes to the volume source or mount path are applied even
	// when the base SPOd already has an older version.
	volumeIndex := slices.IndexFunc(templateSpec.Volumes, func(v corev1.Volume) bool {
		return v.Name == logVolume.Name
	})
	if volumeIndex >= 0 {
		templateSpec.Volumes[volumeIndex] = logVolume
	} else {
		templateSpec.Volumes = append(templateSpec.Volumes, logVolume)
	}

	mountIndex := slices.IndexFunc(ctr.VolumeMounts, func(m corev1.VolumeMount) bool {
		return m.Name == logMount.Name
	})
	if mountIndex >= 0 {
		ctr.VolumeMounts[mountIndex] = logMount
	} else {
		ctr.VolumeMounts = append(ctr.VolumeMounts, logMount)
	}

	return nil
}

// configureAppArmor configures the daemon and the non root enabler to manage
// AppArmor profiles, if enabled.
//
// Loading AppArmor profiles requires write access to the securityfs of the
// host and the host PID namespace, which is why both containers run
// privileged. Unprivileged, CRI-O confines them with its default AppArmor
// profile, which denies both, while it does not confine privileged
// containers. The non root enabler has to load the profiles of the SPOd
// before its containers can start with them.
func configureAppArmor(cfg *spodapi.SecurityProfilesOperatorDaemon, templateSpec *corev1.PodSpec) {
	if !ptr.Deref(cfg.Spec.EnableAppArmor, false) {
		return
	}

	var userRoot int64

	sc := templateSpec.Containers[bindata.ContainerIDDaemon].SecurityContext
	sc.AllowPrivilegeEscalation = new(true)
	sc.Privileged = new(true)
	sc.ReadOnlyRootFilesystem = new(false)
	sc.RunAsUser = &userRoot
	sc.RunAsGroup = &userRoot
	sc.AppArmorProfile = &corev1.AppArmorProfile{
		Type:             corev1.AppArmorProfileTypeLocalhost,
		LocalhostProfile: new(config.SpoApparmorProfileName),
	}

	templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
		templateSpec.Containers[bindata.ContainerIDDaemon].Args,
		"--with-apparmor=true")

	// The init container installs the AppArmor profile of the operator itself.
	templateSpec.InitContainers[bindata.InitContainerIDNonRootenabler].Args = append(
		templateSpec.InitContainers[bindata.InitContainerIDNonRootenabler].Args,
		"--apparmor=true")
	isc := templateSpec.InitContainers[bindata.InitContainerIDNonRootenabler].SecurityContext
	isc.AllowPrivilegeEscalation = new(true)
	isc.Privileged = new(true)
	isc.ReadOnlyRootFilesystem = new(false)
	isc.RunAsUser = &userRoot
	isc.RunAsGroup = &userRoot

	// HostPID is required for AppArmor in order to get access to the host ns
	// when installing the Apparmor profiles.
	templateSpec.HostPID = true
}

// addCapabilities adds the capabilities which the security context does not
// have yet.
func addCapabilities(sc *corev1.SecurityContext, capabilities ...corev1.Capability) {
	if sc.Capabilities == nil {
		sc.Capabilities = &corev1.Capabilities{}
	}

	for _, capability := range capabilities {
		if !slices.Contains(sc.Capabilities.Add, capability) {
			sc.Capabilities.Add = append(sc.Capabilities.Add, capability)
		}
	}
}

// configureContainerDefaults sets the options which apply to all init
// containers and containers.
func configureContainerDefaults(
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	templateSpec *corev1.PodSpec,
	pullPolicy corev1.PullPolicy,
) {
	// Update the SELinux type tag only when AppArmor is not enabled this is to prevent a crash.
	// The SELinux type tag needs to be configured independent of EnableSelinux flag, because the
	// SELinux can be active on the node regardless if the SELinux feature is enabled or not in the operator.
	// For instance, on Flatcar Linux SELinux type tag needs to be set to 'unconfined_t' instead of 'spc_t'
	// even though SELinux is disabled in order to get the containers to start.
	configureSelinuxTag := !ptr.Deref(cfg.Spec.EnableAppArmor, false)

	// The API server only defaults the type tag if the SPOD has a selinux
	// section, and an empty type would drop the one of the base SPOd.
	typeTag := cfg.Spec.Selinux.TypeTag
	if typeTag == "" {
		typeTag = bindata.DefaultSelinuxTypeTag
	}

	for i := range templateSpec.InitContainers {
		ctr := &templateSpec.InitContainers[i]
		ctr.ImagePullPolicy = pullPolicy
		ctr.Env = append(ctr.Env, verbosityEnv(cfg.Spec.Verbosity))

		if configureSelinuxTag {
			configureSeLinuxTag(ctr.SecurityContext, typeTag)
		}
	}

	for i := range templateSpec.Containers {
		ctr := &templateSpec.Containers[i]
		ctr.ImagePullPolicy = pullPolicy
		ctr.Env = append(ctr.Env, verbosityEnv(cfg.Spec.Verbosity))

		if ptr.Deref(cfg.Spec.EnableProfiling, false) {
			enableContainerProfiling(templateSpec, i)
		}

		if configureSelinuxTag {
			configureSeLinuxTag(templateSpec.Containers[i].SecurityContext, typeTag)
		}
	}
}

// pruneUnmountedVolumes drops every volume which no init container or
// container of the rendered pod template uses, either as a volume mount or as
// a raw block volume device, like the kubelet counts volume usage. The base
// SPOd declares the volumes of all optional features (SELinux, log and JSON
// enricher, bpf recorder) unconditionally while their containers are only
// added when the feature is enabled. Without pruning, the hostPath volumes of
// disabled features, like /sys/fs/selinux, /var/log/audit or
// /sys/kernel/debug, stay part of the DaemonSet on every node.
func pruneUnmountedVolumes(templateSpec *corev1.PodSpec) {
	mounted := map[string]bool{}

	for _, containers := range [][]corev1.Container{
		templateSpec.InitContainers, templateSpec.Containers,
	} {
		for i := range containers {
			for _, mount := range containers[i].VolumeMounts {
				mounted[mount.Name] = true
			}

			for _, device := range containers[i].VolumeDevices {
				mounted[device.Name] = true
			}
		}
	}

	volumes := make([]corev1.Volume, 0, len(templateSpec.Volumes))

	for i := range templateSpec.Volumes {
		if mounted[templateSpec.Volumes[i].Name] {
			volumes = append(volumes, templateSpec.Volumes[i])
		}
	}

	templateSpec.Volumes = volumes
}

// bpfCapabilities are the capabilities required to load and attach BPF
// programs.
var bpfCapabilities = []corev1.Capability{"BPF", "PERFMON", "SYS_RESOURCE"}

// hostLogVolumes are the host log directories the log enricher reads with the
// auditd source, which the BPF source does not need.
var hostLogVolumes = []string{"host-auditlog-volume", "host-syslog-volume"}

// configureLogEnricher applies the log enricher configuration to ctr.
func (r *ReconcileSPOd) configureLogEnricher(
	cfg *spodapi.SecurityProfilesOperatorDaemon, ctr *corev1.Container,
) {
	if cfg.Spec.Enricher.LogEnricherFilters != "" {
		r.log.V(config.VerboseLevel).Info("Setting LogEnricherFilters",
			"LogEnricherFilters", cfg.Spec.Enricher.LogEnricherFilters)

		ctr.Args = addArgsConfig(
			ctr.Args,
			"--enricher-filters-json="+cfg.Spec.Enricher.LogEnricherFilters,
		)
	}

	if cfg.Spec.Enricher.LogEnricherSource != "" {
		r.log.V(config.VerboseLevel).Info(
			"Setting LogEnricherSource",
			"LogEnricherSource",
			cfg.Spec.Enricher.LogEnricherSource,
		)

		ctr.Args = addArgsConfig(
			ctr.Args,
			"--enricher-log-source="+string(cfg.Spec.Enricher.LogEnricherSource),
		)
	}

	// The BPF source reads the audit events from the kernel instead of the
	// host log files, so it needs the BPF capabilities but not the logs.
	if cfg.Spec.Enricher.LogEnricherSource == spodapi.LogEnricherSourceBpf {
		addCapabilities(ctr.SecurityContext, bpfCapabilities...)
		ctr.VolumeMounts = slices.DeleteFunc(ctr.VolumeMounts, func(m corev1.VolumeMount) bool {
			return slices.Contains(hostLogVolumes, m.Name)
		})
	}
}

// configureJsonEnricher applies the JSON enricher configuration to ctr.
func (r *ReconcileSPOd) configureJsonEnricher(
	cfg *spodapi.SecurityProfilesOperatorDaemon, ctr *corev1.Container,
) {
	if cfg.Spec.Enricher.JsonEnricherFilters != "" {
		r.log.V(config.VerboseLevel).Info("Setting JsonEnricherFilters",
			"JsonEnricherFilters", cfg.Spec.Enricher.JsonEnricherFilters)

		ctr.Args = addArgsConfig(
			ctr.Args,
			"--enricher-filters-json="+cfg.Spec.Enricher.JsonEnricherFilters,
		)
	}

	opts := cfg.Spec.Enricher.JsonEnricherOptions
	if opts == nil {
		return
	}

	r.log.V(config.VerboseLevel).Info(
		"Setting JsonEnricherOpt",
		"AuditLogIntervalSeconds", opts.AuditLogIntervalSeconds,
		"AuditLogPath", opts.AuditLogPath,
		"AuditLogMaxAge", opts.AuditLogMaxAge,
		"AuditLogMaxSize", opts.AuditLogMaxSize,
		"AuditLogMaxBackups", opts.AuditLogMaxBackups,
	)

	if opts.AuditLogIntervalSeconds != nil {
		ctr.Args = addArgsConfig(ctr.Args,
			fmt.Sprintf("--audit-log-interval-seconds=%d", *opts.AuditLogIntervalSeconds))
	}

	if opts.AuditLogMaxAge != nil {
		ctr.Args = addArgsConfig(ctr.Args,
			fmt.Sprintf("--audit-log-maxage=%d", *opts.AuditLogMaxAge))
	}

	if opts.AuditLogMaxSize != nil {
		ctr.Args = addArgsConfig(ctr.Args,
			fmt.Sprintf("--audit-log-maxsize=%d", *opts.AuditLogMaxSize))
	}

	if opts.AuditLogMaxBackups != nil {
		ctr.Args = addArgsConfig(ctr.Args,
			fmt.Sprintf("--audit-log-maxbackup=%d", *opts.AuditLogMaxBackups))
	}

	if opts.AuditLogPath != nil {
		ctr.Args = addArgsConfig(ctr.Args, "--audit-log-path="+*opts.AuditLogPath)
	}
}

// getConfiguredWebook gets a fully configured webhook instance from a desired
// configuration and the reference base SPOd.
func (r *ReconcileSPOd) getConfiguredWebook(cfg *spodapi.SecurityProfilesOperatorDaemon,
	image string, pullPolicy corev1.PullPolicy, caInjectType bindata.CAInjectType,
) *bindata.Webhook {
	webhookTolerations := cfg.Spec.Webhook.Tolerations
	if len(webhookTolerations) == 0 {
		webhookTolerations = cfg.Spec.Scheduling.Tolerations
	}

	webhook := bindata.GetWebhook(
		r.log,
		r.namespace,
		cfg.Spec.Webhook.Options,
		image,
		pullPolicy,
		caInjectType,
		webhookTolerations,
		cfg.Spec.ImagePullSecrets,
		r.isExecMetadataEnabled(cfg),
	)
	webhook.UseDaemonPriorityClass(cfg.Spec.Scheduling.PriorityClassName)

	return webhook
}

// isExecMetadataEnabled returns true if the exec metadata webhook gets
// deployed, which is the case if the JSON enricher is enabled and the
// webhook is not disabled explicitly.
func (r *ReconcileSPOd) isExecMetadataEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	return r.isJsonEnricherEnabled(cfg) && ptr.Deref(cfg.Spec.Enricher.EnableExecMetadata, true)
}

func addSelinuxCustomTemplatesVolume(
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	templateSpec *corev1.PodSpec,
) error {
	if cfg.Spec.Selinux.CustomTemplatesConfigMap == "" {
		return nil
	}

	idx := slices.IndexFunc(templateSpec.InitContainers, func(c corev1.Container) bool {
		return c.Name == bindata.SelinuxPoliciesCopierContainerName
	})
	if idx == -1 {
		return fmt.Errorf(
			"customTemplatesConfigMap is set but %s init container was not found",
			bindata.SelinuxPoliciesCopierContainerName,
		)
	}

	vol, mount := bindata.CustomTemplatesVolume(cfg.Spec.Selinux.CustomTemplatesConfigMap)
	templateSpec.Volumes = append(templateSpec.Volumes, vol)
	templateSpec.InitContainers[idx].VolumeMounts = append(
		templateSpec.InitContainers[idx].VolumeMounts,
		mount,
	)

	return nil
}

// envFlags are the features which the environment of the operator enables
// in addition to the SPOD. They are read once in Setup.
type envFlags struct {
	enableLogEnricher           bool
	enableJsonEnricher          bool
	enableBpfRecorder           bool
	enableInsecureMetricsAccess bool
}

// envFlagsFromEnvironment reads the feature flags from the environment of
// the operator. Values which are not a boolean disable the feature.
func envFlagsFromEnvironment() envFlags {
	return envFlags{
		enableLogEnricher:           envBool(config.EnableLogEnricherEnvKey),
		enableJsonEnricher:          envBool(config.EnableJsonEnricherEnvKey),
		enableBpfRecorder:           envBool(config.EnableBpfRecorderEnvKey),
		enableInsecureMetricsAccess: envBool(config.EnableInsecureMetricsAccessEnvKey),
	}
}

// envBool returns true if the environment variable is a true boolean.
func envBool(key string) bool {
	value, err := strconv.ParseBool(os.Getenv(key))

	return err == nil && value
}

// byEnvKey returns the flag of the environment variable.
func (e envFlags) byEnvKey(key string) bool {
	switch key {
	case config.EnableLogEnricherEnvKey:
		return e.enableLogEnricher
	case config.EnableJsonEnricherEnvKey:
		return e.enableJsonEnricher
	case config.EnableBpfRecorderEnvKey:
		return e.enableBpfRecorder
	case config.EnableInsecureMetricsAccessEnvKey:
		return e.enableInsecureMetricsAccess
	default:
		return false
	}
}

func (r *ReconcileSPOd) isLogEnricherEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	return ptr.Deref(cfg.Spec.Enricher.EnableLogEnricher, false) || r.env.enableLogEnricher
}

func (r *ReconcileSPOd) isJsonEnricherEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	return ptr.Deref(cfg.Spec.Enricher.EnableJsonEnricher, false) || r.env.enableJsonEnricher
}

func (r *ReconcileSPOd) isInsecureMetricsEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	return ptr.Deref(cfg.Spec.EnableInsecureMetricsAccess, false) ||
		r.env.enableInsecureMetricsAccess
}

func (r *ReconcileSPOd) isBpfRecorderEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	return ptr.Deref(cfg.Spec.Enricher.EnableBpfRecorder, false) || r.env.enableBpfRecorder
}

func addArgsConfig(args []string, argonfig string) []string {
	if replaced := sliceReplaceArg(args, argonfig); replaced {
		return args
	}

	if !sliceContainsString(args, argonfig) {
		return append(args, argonfig)
	}

	return args
}

func sliceReplaceArg(slice []string, s string) bool {
	const argSeparator = "="

	newParts := strings.SplitN(s, argSeparator, 2)
	if len(newParts) != 2 {
		return false
	}

	newKey := newParts[0]

	for i := range slice {
		existingItem := slice[i]
		existingParts := strings.SplitN(
			existingItem,
			argSeparator,
			2,
		) // Split existing item to get its key

		if len(existingParts) >= 1 && existingParts[0] == newKey {
			slice[i] = s

			return true
		}
	}

	return false
}

func sliceContainsString(slice []string, s string) bool {
	return slices.Contains(slice, s)
}

// addEnvVar passes the flag of the operator environment to the daemon.
func (r *ReconcileSPOd) addEnvVar(templateSpec *corev1.PodSpec, envVarKey string) {
	envVar := corev1.EnvVar{
		Name:  envVarKey,
		Value: strconv.FormatBool(r.env.byEnvKey(envVarKey)),
	}

	templateSpec.Containers[bindata.ContainerIDDaemon].Env = append(
		templateSpec.Containers[bindata.ContainerIDDaemon].Env,
		envVar)
}

func configureSeLinuxTag(secContext *corev1.SecurityContext, seLinuxTag string) {
	if secContext == nil {
		return
	}

	if secContext.SELinuxOptions == nil {
		secContext.SELinuxOptions = &corev1.SELinuxOptions{}
	}

	secContext.SELinuxOptions.Type = seLinuxTag
}

func verbosityEnv(value int32) corev1.EnvVar {
	return corev1.EnvVar{
		Name:  config.VerbosityEnvKey,
		Value: strconv.FormatInt(int64(value), 10),
	}
}

func enableContainerProfiling(templateSpec *corev1.PodSpec, cID int) {
	containerName := templateSpec.Containers[cID].Name
	switch containerName {
	case bindata.SelinuxContainerName:
		templateSpec.Containers[cID].Args = append(
			templateSpec.Containers[cID].Args,
			profilingArgsSelinuxd()...,
		)
	default:
		templateSpec.Containers[cID].Env = append(
			templateSpec.Containers[cID].Env,
			profilingEnvsSpo(cID)...,
		)
	}
}

func profilingArgsSelinuxd() []string {
	return []string{"--enable-profiling=true"}
}

// profilingEnvsSpo returns the profiling environment of a SPOd container.
// The profiling endpoint binds to the pod address, because enabling it in the
// SPOD is the explicit request to reach it from outside the pod, while the
// binary defaults to the loopback interface.
func profilingEnvsSpo(add int) []corev1.EnvVar {
	return []corev1.EnvVar{
		{
			Name:  config.ProfilingEnvKey,
			Value: "true",
		},
		{
			Name:  config.ProfilingPortEnvKey,
			Value: strconv.Itoa(config.DefaultProfilingPort + add),
		},
		{
			Name:  config.ProfilingAddressEnvKey,
			Value: config.AllInterfacesAddress,
		},
	}
}

func spodNeedsUpdate(configured, found *appsv1.DaemonSet) bool {
	cSpec, fSpec := &configured.Spec.Template.Spec, &found.Spec.Template.Spec

	// If the length of the containers or volumes don't match, we clearly need
	// an update. This way we avoid the expensive DeepDerivative check, and the
	// volume count also catches a pruned trailing volume, which DeepDerivative
	// would accept as a prefix match of the longer slice in the found object.
	// The same applies to the arguments, environment variables and volume
	// mounts of the containers, for example when profiling gets disabled.
	// DeepDerivative also ignores fields which are unset in the configured
	// object, so the scheduling fields are compared explicitly to detect when
	// they got cleared. The legacy AppArmor annotation only needs to be removed.
	return (len(cSpec.InitContainers) != len(fSpec.InitContainers) ||
		len(cSpec.Containers) != len(fSpec.Containers) ||
		len(cSpec.Volumes) != len(fSpec.Volumes) ||
		containerListsDiffer(cSpec.InitContainers, fSpec.InitContainers) ||
		containerListsDiffer(cSpec.Containers, fSpec.Containers) ||
		cSpec.PriorityClassName != fSpec.PriorityClassName ||
		!apiequality.Semantic.DeepEqual(cSpec.Affinity, fSpec.Affinity) ||
		!apiequality.Semantic.DeepEqual(cSpec.Tolerations, fSpec.Tolerations) ||
		!apiequality.Semantic.DeepEqual(cSpec.ImagePullSecrets, fSpec.ImagePullSecrets) ||
		found.Annotations[legacyAppArmorAnnotation] != "" ||
		!apiequality.Semantic.DeepDerivative(configured.Spec.Template, found.Spec.Template))
}

// containerListsDiffer reports if the containers at the same index have a
// different number of arguments, environment variables or volume mounts, a
// readiness probe on one side only, or different resources or security
// contexts. DeepDerivative ignores fields which are unset in the configured
// container, so these get compared explicitly to detect cleared ones, like a
// removed limit. Both lists are expected to have the same length.
func containerListsDiffer(configured, found []corev1.Container) bool {
	for i := range configured {
		if len(configured[i].Args) != len(found[i].Args) ||
			len(configured[i].Env) != len(found[i].Env) ||
			len(configured[i].VolumeMounts) != len(found[i].VolumeMounts) ||
			(configured[i].ReadinessProbe == nil) != (found[i].ReadinessProbe == nil) ||
			!apiequality.Semantic.DeepEqual(configured[i].Resources, found[i].Resources) ||
			securityContextsDiffer(configured[i].SecurityContext, found[i].SecurityContext) {
			return true
		}
	}

	return false
}

// securityContextsDiffer reports if the security contexts differ. The proc
// mount type is ignored if it is not configured, because the API server may
// default it.
func securityContextsDiffer(configured, found *corev1.SecurityContext) bool {
	if configured != nil && found != nil && configured.ProcMount == nil {
		configured = configured.DeepCopy()
		configured.ProcMount = found.ProcMount
	}

	return !apiequality.Semantic.DeepEqual(configured, found)
}
