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

	reasonCannotCreateSPOD           string = "CannotCreateSPOD"
	reasonCannotUpdateSPOD           string = "CannotUpdateSPOD"
	reasonCannotMountCustomTemplates string = "CannotMountCustomTemplates"
	reasonInvalidKubeletDirLabel     string = "InvalidKubeletDirLabel"

	reasonCannotApplyAdmissionPolicies string = "CannotApplyAdmissionPolicies"

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

	// kubeletDirMu guards invalidKubeletDirLabels, which maps the nodes with
	// an invalid kubelet directory label to the reported label value.
	kubeletDirMu            sync.Mutex
	invalidKubeletDirLabels map[string]string
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
// Used for event generation:
// +kubebuilder:rbac:groups=core,resources=events,verbs=create
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update
//
// Operand, which lives in the operator namespace. The manager cache for these
// kinds is restricted to that namespace by the manager command.
// +kubebuilder:rbac:groups="",namespace="security-profiles-operator",resources=services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=deployments;daemonsets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets/finalizers,verbs=get;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,namespace="security-profiles-operator",resources=issuers;certificates,verbs=get;list;watch;create;update;patch
//
// Webhook configurations are cluster scoped. Create cannot be restricted by
// name, but modifications are limited to the operator owned configurations.
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations;validatingwebhookconfigurations,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,resourceNames=spo-mutating-webhook-configuration,verbs=update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,resourceNames=spo-validating-webhook-configuration,verbs=update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/finalizers,verbs=delete;get;update;patch
// Helpers:
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update
//
// Needed for default profiles:
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
//
// Needed for the ServiceMonitor
// +kubebuilder:rbac:groups=monitoring.coreos.com,namespace="security-profiles-operator",resources=servicemonitors,verbs=get;list;watch;create;update;patch
//
// OpenShift (This is ignored in other distros):
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resourceNames=restricted-v2,resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators,verbs=get;list;watch
// +kubebuilder:rbac:groups=config.openshift.io,resources=apiservers,verbs=get;list;watch
//
// Needed to detect which runtime is active and custom kubelet directories
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
//
// Needed to detect the proper selinux image
// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=security-profiles-operator-profile,verbs=get
//
// Needed to authenticate and authorize metrics requests
// +kubebuilder:rbac:groups=authentication.k8s.io,resources=tokenreviews,verbs=create
// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create
//
// Needed for the admission policies, see bindata.AdmissionPolicies
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,verbs=get;list;watch;create
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,resourceNames=spo-recording-profiles,verbs=update

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

	deploymentKey := types.NamespacedName{
		Name:      config.OperatorName,
		Namespace: r.namespace,
	}
	foundDeployment := &appsv1.Deployment{}

	if err := r.client.Get(ctx, deploymentKey, foundDeployment); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("get operator deployment: %w", err)
	}
	// We use the same target image for the deamonset as which we have right
	// now running.
	image := foundDeployment.Spec.Template.Spec.Containers[0].Image
	pullPolicy := foundDeployment.Spec.Template.Spec.Containers[0].ImagePullPolicy

	spodKey := types.NamespacedName{
		Name:      spod.GetName(),
		Namespace: r.namespace,
	}

	caInjectType, err := bindata.GetCAInjectType(ctx, r.log, r.client)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("get ca inject type: %w", err)
	}

	configuredSPOd, err := r.getConfiguredSPOd(ctx, spod, image, pullPolicy, caInjectType)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("get configured SPOD: %w", err)
	}

	kubeletDirs, err := r.nodeKubeletDirs(ctx, spod)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("get node kubelet directories: %w", err)
	}

	webhook := r.getConfiguredWebook(spod, image, pullPolicy, caInjectType)
	r.applyAdmissionPolicies(ctx, spod, webhook)

	metricsService := bindata.GetMetricsService(r.namespace, caInjectType)
	serviceMonitor := bindata.ServiceMonitor(caInjectType,
		ptr.Deref(spod.Spec.EnableInsecureMetricsAccess, false))

	var certManagerResources *bindata.CertManagerResources
	if caInjectType == bindata.CAInjectTypeCertManager {
		certManagerResources = bindata.GetCertManagerResources(r.namespace)
	}

	foundSPOd := &appsv1.DaemonSet{}
	if err := r.client.Get(ctx, spodKey, foundSPOd); err != nil {
		if errors.IsNotFound(err) {
			addKubeletDirVolumes(&configuredSPOd.Spec.Template.Spec, kubeletDirs)

			createErr := r.handleCreate(
				ctx,
				spod,
				configuredSPOd,
				webhook,
				metricsService,
				certManagerResources,
				serviceMonitor,
			)
			if createErr != nil {
				r.record.Eventf(
					spod,
					nil,
					util.EventTypeWarning,
					reasonCannotCreateSPOD,
					util.EventActionReconcile,
					"%s",
					createErr.Error(),
				)

				return reconcile.Result{}, createErr
			}

			return reconcile.Result{}, r.handleCreatingStatus(ctx, spod, logger)
		}

		return reconcile.Result{}, fmt.Errorf("getting spod DaemonSet: %w", err)
	}

	addKubeletDirVolumes(
		&configuredSPOd.Spec.Template.Spec,
		kubeletDirsToMount(configuredSPOd, foundSPOd, kubeletDirs),
	)

	spodUpdate := spodNeedsUpdate(configuredSPOd, foundSPOd)

	var hookUpdate bool
	if !ptr.Deref(spod.Spec.Webhook.StaticConfig, false) {
		hookUpdate, err = webhook.NeedsUpdate(ctx, r.client)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("determining if webhook needs update: %w", err)
		}
	}

	if spodUpdate || hookUpdate {
		r.log.Info("Updating spod", "spodUpdate", spodUpdate, "hookUpdate", hookUpdate)

		updatedSPod := foundSPOd.DeepCopy()
		updatedSPod.Spec.Template = configuredSPOd.Spec.Template
		delete(updatedSPod.Annotations, legacyAppArmorAnnotation)

		updateErr := r.handleUpdate(
			ctx, spod, updatedSPod, webhook, metricsService, certManagerResources, serviceMonitor,
		)
		if updateErr != nil {
			r.record.Eventf(
				spod,
				nil,
				util.EventTypeWarning,
				reasonCannotUpdateSPOD,
				util.EventActionUpdate,
				"%s",
				updateErr.Error(),
			)

			return reconcile.Result{}, updateErr
		}

		return reconcile.Result{}, r.handleUpdatingStatus(ctx, spod, logger)
	}

	if foundSPOd.Status.NumberReady == foundSPOd.Status.DesiredNumberScheduled {
		condready := spod.Status.GetReadyCondition()
		// Don't pollute the logs. Let's only update when needed.
		if condready.Status != metav1.ConditionTrue {
			return reconcile.Result{}, r.handleRunningStatus(ctx, spod, logger)
		}
	}

	return reconcile.Result{}, nil
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

func (r *ReconcileSPOd) handleInitialStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (err error) {
	l.Info("Adding an initial status to the SPOD instance")

	sCopy := spod.DeepCopy()
	sCopy.Status.StatePending()

	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return fmt.Errorf("updating spod initial status: %w", updateErr)
	}

	return nil
}

func (r *ReconcileSPOd) handleCreatingStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (err error) {
	l.Info("Adding 'Creating' status to the SPOD instance")

	sCopy := spod.DeepCopy()
	sCopy.Status.StateCreating()

	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return fmt.Errorf("updating spod status to creating: %w", updateErr)
	}

	return nil
}

func (r *ReconcileSPOd) handleUpdatingStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (err error) {
	l.Info("Adding 'Updating' status to the SPOD instance")

	sCopy := spod.DeepCopy()
	sCopy.Status.StateUpdating()

	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return fmt.Errorf("updating spod status to 'updating': %w", updateErr)
	}

	return nil
}

func (r *ReconcileSPOd) defaultProfiles(
	cfg *spodapi.SecurityProfilesOperatorDaemon,
) (defaultProfiles []*seccompprofileapi.SeccompProfile) {
	if ptr.Deref(cfg.Spec.Enricher.EnableLogEnricher, false) {
		defaultProfiles = append(defaultProfiles, bindata.DefaultLogEnricherProfile())
	}

	return defaultProfiles
}

func (r *ReconcileSPOd) handleRunningStatus(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (err error) {
	l.Info("Adding 'Running' status to the SPOD instance")

	sCopy := spod.DeepCopy()
	sCopy.Status.StateRunning()

	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return fmt.Errorf("updating spod status to running: %w", updateErr)
	}

	return nil
}

func (r *ReconcileSPOd) handleCreate(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	newSPOd *appsv1.DaemonSet,
	webhook *bindata.Webhook,
	metricsService *corev1.Service,
	certManagerResources *bindata.CertManagerResources,
	serviceMonitor *monitoringv1.ServiceMonitor,
) error {
	if certManagerResources != nil {
		r.log.Info("Deploying cert manager resources")

		if err := certManagerResources.Create(ctx, r.client); err != nil {
			return fmt.Errorf("creating cert manager resources: %w", err)
		}
	}

	if !ptr.Deref(cfg.Spec.Webhook.StaticConfig, false) {
		r.log.Info("Deploying operator webhook")

		if err := webhook.Create(ctx, r.client); err != nil {
			return fmt.Errorf("creating webhook: %w", err)
		}
	}

	r.log.Info("Creating operator resources")

	if err := controllerutil.SetControllerReference(cfg, newSPOd, r.scheme); err != nil {
		return fmt.Errorf("setting spod controller reference: %w", err)
	}

	r.log.Info("Deploying operator daemonset")

	if err := r.client.Create(ctx, newSPOd); err != nil && !errors.IsAlreadyExists(err) {
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

	if err := r.client.Create(ctx, metricsService); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("creating metrics service: %w", err)
	}

	r.log.Info("Deploying operator service monitor")

	if err := r.client.Create(
		ctx, serviceMonitor,
	); err != nil {
		//nolint:gocritic
		if bindata.IsNotFound(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else if errors.IsAlreadyExists(err) {
			r.log.Info("Service monitor already exist, skipping")
		} else {
			return fmt.Errorf("creating service monitor: %w", err)
		}
	}

	return nil
}

func (r *ReconcileSPOd) handleUpdate(
	ctx context.Context,
	cfg *spodapi.SecurityProfilesOperatorDaemon,
	spodInstance *appsv1.DaemonSet,
	webhook *bindata.Webhook,
	metricsService *corev1.Service,
	certManagerResources *bindata.CertManagerResources,
	serviceMonitor *monitoringv1.ServiceMonitor,
) error {
	if certManagerResources != nil {
		r.log.Info("Updating cert manager resources")

		if err := certManagerResources.Update(ctx, r.client); err != nil {
			return fmt.Errorf("updating cert manager resources: %w", err)
		}
	}

	if !ptr.Deref(cfg.Spec.Webhook.StaticConfig, false) {
		r.log.Info("Updating operator webhook")

		if err := webhook.Update(ctx, r.client); err != nil {
			return fmt.Errorf("updating webhook: %w", err)
		}
	}

	r.log.Info("Updating operator daemonset")

	// A JSON merge patch would keep fields which got cleared in the
	// configuration, like the affinity, so update the whole object instead.
	if err := r.client.Update(ctx, spodInstance); err != nil {
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

	if err := r.client.Patch(ctx, metricsService, client.Merge); err != nil {
		return fmt.Errorf("updating metrics service: %w", err)
	}

	r.log.Info("Updating operator service monitor")

	if err := r.client.Patch(
		ctx, serviceMonitor, client.Merge,
	); err != nil {
		if bindata.IsNotFound(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else {
			return fmt.Errorf("updating service monitor: %w", err)
		}
	}

	return nil
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

	r.configureRecording(ctx, cfg, templateSpec, image)
	configureAppArmor(cfg, templateSpec)

	// Enable memory optimization for spod controller
	if ptr.Deref(cfg.Spec.EnableMemoryOptimization, false) {
		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-mem-optim=true")
	}

	if isInsecureMetricsEnabled(cfg) {
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
) {
	// Custom host proc volume
	useCustomHostProc := cfg.Spec.HostProcVolumePath != bindata.DefaultHostProcPath &&
		cfg.Spec.HostProcVolumePath != ""
	volume, mount := bindata.CustomHostProcVolume(cfg.Spec.HostProcVolumePath)

	// Disable profile recording controller by default
	enableRecording := false

	if isLogEnricherEnabled(cfg) || isBpfRecorderEnabled(cfg) || isJsonEnricherEnabled(cfg) {
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
		addEnvVar(templateSpec, envKey)
	}

	if isLogEnricherEnabled(cfg) {
		addContainer(bindata.ContainerIDLogEnricher, config.EnableLogEnricherEnvKey,
			func(ctr *corev1.Container) { r.configureLogEnricher(cfg, ctr) })
	}

	if isBpfRecorderEnabled(cfg) {
		addContainer(bindata.ContainerIDBpfRecorder, config.EnableBpfRecorderEnvKey,
			func(ctr *corev1.Container) {
				// Configure the apparmor profile for bpf-recorder when apparmor is enabled.
				if ptr.Deref(cfg.Spec.EnableAppArmor, false) {
					ctr.SecurityContext.AppArmorProfile = &corev1.AppArmorProfile{
						Type:             corev1.AppArmorProfileTypeLocalhost,
						LocalhostProfile: new(config.BpfRecorderApparmorProfileName),
					}
				}
			})
	}

	if isJsonEnricherEnabled(cfg) {
		addContainer(bindata.ContainerIDJsonEnricher, config.EnableJsonEnricherEnvKey,
			func(ctr *corev1.Container) {
				r.addJsonEnricherLogVolume(ctx, templateSpec, ctr)
				r.configureJsonEnricher(cfg, ctr)
			})
	}
}

// addJsonEnricherLogVolume adds the optional log volume of the json enricher.
// Its configuration is read from the ConfigMap during each reconciliation to
// handle ConfigMap updates without requiring an operator restart.
func (r *ReconcileSPOd) addJsonEnricherLogVolume(
	ctx context.Context,
	templateSpec *corev1.PodSpec,
	ctr *corev1.Container,
) {
	logVolumeSource, logVolumeMountPath, err := r.getJsonEnricherVolume(ctx)
	if err != nil || logVolumeSource == nil {
		return
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
}

// configureAppArmor configures the daemon and the non root enabler to manage
// AppArmor profiles, if enabled.
//
// Loading AppArmor profiles requires write access to the securityfs of the
// host and the host PID namespace, which is why both containers run
// privileged. Replacing that with dedicated capabilities requires runtime
// validation on AppArmor enabled nodes.
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

	for i := range templateSpec.InitContainers {
		ctr := &templateSpec.InitContainers[i]
		ctr.ImagePullPolicy = pullPolicy
		ctr.Env = append(ctr.Env, verbosityEnv(cfg.Spec.Verbosity))

		if configureSelinuxTag {
			configureSeLinuxTag(ctr.SecurityContext, cfg.Spec.Selinux.TypeTag)
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
			configureSeLinuxTag(
				templateSpec.Containers[i].SecurityContext,
				cfg.Spec.Selinux.TypeTag,
			)
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

// configureLogEnricher applies the log enricher configuration to ctr.
func (r *ReconcileSPOd) configureLogEnricher(
	cfg *spodapi.SecurityProfilesOperatorDaemon, ctr *corev1.Container,
) {
	if cfg.Spec.Enricher.LogEnricherFilters != "" {
		r.log.Info("Setting LogEnricherFilters",
			"LogEnricherFilters", cfg.Spec.Enricher.LogEnricherFilters)

		ctr.Args = addArgsConfig(
			ctr.Args,
			"--enricher-filters-json="+cfg.Spec.Enricher.LogEnricherFilters,
		)
	}

	if cfg.Spec.Enricher.LogEnricherSource != "" {
		r.log.Info(
			"Setting LogEnricherSource",
			"LogEnricherSource",
			cfg.Spec.Enricher.LogEnricherSource,
		)

		ctr.Args = addArgsConfig(
			ctr.Args,
			"--enricher-log-source="+string(cfg.Spec.Enricher.LogEnricherSource),
		)
	}
}

// configureJsonEnricher applies the JSON enricher configuration to ctr.
func (r *ReconcileSPOd) configureJsonEnricher(
	cfg *spodapi.SecurityProfilesOperatorDaemon, ctr *corev1.Container,
) {
	if cfg.Spec.Enricher.JsonEnricherFilters != "" {
		r.log.Info("Setting JsonEnricherFilters",
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

	r.log.Info(
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
		isJsonEnricherEnabled(cfg),
	)

	return webhook
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

func isLogEnricherEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	enableLogEnricherEnv, err := strconv.ParseBool(os.Getenv(config.EnableLogEnricherEnvKey))
	if err != nil {
		enableLogEnricherEnv = false
	}

	return ptr.Deref(cfg.Spec.Enricher.EnableLogEnricher, false) || enableLogEnricherEnv
}

func isJsonEnricherEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	enableJsonEnricherEnv, err := strconv.ParseBool(os.Getenv(config.EnableJsonEnricherEnvKey))
	if err != nil {
		enableJsonEnricherEnv = false
	}

	return ptr.Deref(cfg.Spec.Enricher.EnableJsonEnricher, false) || enableJsonEnricherEnv
}

func isInsecureMetricsEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	enableInsecureMetricsEnv, err := strconv.ParseBool(
		os.Getenv(config.EnableInsecureMetricsAccessEnvKey),
	)
	if err != nil {
		enableInsecureMetricsEnv = false
	}

	return ptr.Deref(cfg.Spec.EnableInsecureMetricsAccess, false) || enableInsecureMetricsEnv
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

func isBpfRecorderEnabled(cfg *spodapi.SecurityProfilesOperatorDaemon) bool {
	enableBpfRecorderEnv, err := strconv.ParseBool(os.Getenv(config.EnableBpfRecorderEnvKey))
	if err != nil {
		enableBpfRecorderEnv = false
	}

	return ptr.Deref(cfg.Spec.Enricher.EnableBpfRecorder, false) || enableBpfRecorderEnv
}

func addEnvVar(templateSpec *corev1.PodSpec, envVarKey string) {
	envValue, err := strconv.ParseBool(os.Getenv(envVarKey))
	if err != nil {
		envValue = false
	}

	envVar := corev1.EnvVar{
		Name:  envVarKey,
		Value: strconv.FormatBool(envValue),
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
// different number of arguments, environment variables or volume mounts. Both
// lists are expected to have the same length.
func containerListsDiffer(configured, found []corev1.Container) bool {
	for i := range configured {
		if len(configured[i].Args) != len(found[i].Args) ||
			len(configured[i].Env) != len(found[i].Env) ||
			len(configured[i].VolumeMounts) != len(found[i].VolumeMounts) {
			return true
		}
	}

	return false
}
