/*
Copyright 2020 The Kubernetes Authors.

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
	"strconv"
	"time"

	"github.com/go-logr/logr"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	reasonCannotCreateSPOD string = "CannotCreateSPOD"
	reasonCannotUpdateSPOD string = "CannotUpdateSPOD"

	appArmorAnnotation = "container.seccomp.security.alpha.kubernetes.io/security-profiles-operator"
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
	clientReader   client.Reader
	scheme         *runtime.Scheme
	baseSPOd       *appsv1.DaemonSet
	record         record.EventRecorder
	log            logr.Logger
	watchNamespace string
	namespace      string
}

// Name returns the name of the controller.
func (r *ReconcileSPOd) Name() string {
	return "spod-config"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReconcileSPOd) SchemeBuilder() *scheme.Builder {
	return spodv1alpha1.SchemeBuilder
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
//
// Operand:
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=cert-manager.io,resources=issuers;certificates,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/finalizers,verbs=delete;get;update;patch
// Helpers:
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update;
//
// Needed for default profiles:
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
//
// Needed for the ServiceMonitor
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=servicemonitors,verbs=get;list;watch;create;update;patch
//
// OpenShift (This is ignored in other distros):
// +kubebuilder:rbac:groups=security.openshift.io,namespace="security-profiles-operator",resources=securitycontextconstraints,verbs=use
// +kubebuilder:rbac:groups=config.openshift.io,resources=clusteroperators,verbs=get;list;watch
//
// Needed to detect which runtime is active
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;get
//
// Needed to detect the proper selinux image
// +kubebuilder:rbac:groups="",resources=configmaps,resourceNames=security-profiles-operator-profile,verbs=get

// Reconcile reads that state of the cluster for a SPOD object and makes changes based on the state read
// and what is in the `ConfigMap.Spec`.
func (r *ReconcileSPOd) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)
	// Fetch the ConfigMap instance
	spod := &spodv1alpha1.SecurityProfilesOperatorDaemon{}
	if err := r.client.Get(ctx, req.NamespacedName, spod); err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("getting spod configuration: %w", err)
	}

	if spod.Status.State == "" {
		return r.handleInitialStatus(ctx, spod, logger)
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

	caInjectType, err := bindata.GetCAInjectType(ctx, r.log, r.namespace, r.client)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("get ca inject type: %w", err)
	}
	configuredSPOd := r.getConfiguredSPOd(spod, image, pullPolicy, caInjectType)

	webhook := bindata.GetWebhook(r.log, r.namespace, spod.Spec.WebhookOpts, image,
		pullPolicy, caInjectType, spod.Spec.Tolerations, spod.Spec.ImagePullSecrets)
	metricsService := bindata.GetMetricsService(r.namespace, caInjectType)
	serviceMonitor := bindata.ServiceMonitor(caInjectType)

	var certManagerResources *bindata.CertManagerResources
	if caInjectType == bindata.CAInjectTypeCertManager {
		certManagerResources = bindata.GetCertManagerResources(r.namespace)
	}

	foundSPOd := &appsv1.DaemonSet{}
	if err := r.client.Get(ctx, spodKey, foundSPOd); err != nil {
		if errors.IsNotFound(err) {
			createErr := r.handleCreate(
				ctx, spod, configuredSPOd, webhook, metricsService, certManagerResources, serviceMonitor,
			)
			if createErr != nil {
				r.record.Event(spod, util.EventTypeWarning, reasonCannotCreateSPOD, createErr.Error())
				return reconcile.Result{}, createErr
			}
			return r.handleCreatingStatus(ctx, spod, logger)
		}
		return reconcile.Result{}, fmt.Errorf("getting spod DaemonSet: %w", err)
	}

	spodUpdate := spodNeedsUpdate(configuredSPOd, foundSPOd)

	var hookUpdate bool
	if !spod.Spec.StaticWebhookConfig {
		hookUpdate, err = webhook.NeedsUpdate(ctx, r.client)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("determining if webhook needs update: %w", err)
		}
	}

	if spodUpdate || hookUpdate {
		updatedSPod := foundSPOd.DeepCopy()
		updatedSPod.Spec.Template = configuredSPOd.Spec.Template
		updateErr := r.handleUpdate(
			ctx, spod, updatedSPod, webhook, metricsService, certManagerResources, serviceMonitor,
		)
		if updateErr != nil {
			r.record.Event(spod, util.EventTypeWarning, reasonCannotUpdateSPOD, updateErr.Error())
			return reconcile.Result{}, updateErr
		}
		return r.handleUpdatingStatus(ctx, spod, logger)
	}

	if foundSPOd.Status.NumberReady == foundSPOd.Status.DesiredNumberScheduled {
		condready := spod.Status.GetReadyCondition()
		// Don't pollute the logs. Let's only update when needed.
		if condready.Status != corev1.ConditionTrue {
			return r.handleRunningStatus(ctx, spod, logger)
		}
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleInitialStatus(
	ctx context.Context,
	spod *spodv1alpha1.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (res reconcile.Result, err error) {
	l.Info("Adding an initial status to the SPOD Instance")
	sCopy := spod.DeepCopy()
	sCopy.Status.StatePending()
	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return reconcile.Result{}, fmt.Errorf("updating spod initial status: %w", updateErr)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleCreatingStatus(
	ctx context.Context,
	spod *spodv1alpha1.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (res reconcile.Result, err error) {
	l.Info("Adding 'Creating' status to the SPOD Instance")
	sCopy := spod.DeepCopy()
	sCopy.Status.StateCreating()
	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return reconcile.Result{}, fmt.Errorf("updating spod status to creating: %w", updateErr)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleUpdatingStatus(
	ctx context.Context,
	spod *spodv1alpha1.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (res reconcile.Result, err error) {
	l.Info("Adding 'Updating' status to the SPOD Instance")
	sCopy := spod.DeepCopy()
	sCopy.Status.StateUpdating()
	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return reconcile.Result{}, fmt.Errorf("updating spod status to 'updating': %w", updateErr)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) defaultProfiles(
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
) (defaultProfiles []*seccompprofileapi.SeccompProfile) {
	if cfg.Spec.EnableLogEnricher {
		defaultProfiles = append(defaultProfiles, bindata.DefaultLogEnricherProfile())
	}
	return defaultProfiles
}

func (r *ReconcileSPOd) handleRunningStatus(
	ctx context.Context,
	spod *spodv1alpha1.SecurityProfilesOperatorDaemon,
	l logr.Logger,
) (res reconcile.Result, err error) {
	l.Info("Adding 'Running' status to the SPOD Instance")
	sCopy := spod.DeepCopy()
	sCopy.Status.StateRunning()
	updateErr := r.client.Status().Update(ctx, sCopy)
	if updateErr != nil {
		return reconcile.Result{}, fmt.Errorf("updating spod status to running: %w", updateErr)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleCreate(
	ctx context.Context,
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
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

	if !cfg.Spec.StaticWebhookConfig {
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
	if err := r.client.Create(ctx, newSPOd); err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("creating operator DaemonSet: %w", err)
	}

	r.log.Info("Deploying operator default profiles")
	for _, profile := range r.defaultProfiles(cfg) {
		// Adapt the namespace if we watch only a single one
		if r.watchNamespace != "" {
			profile.Namespace = r.watchNamespace
		}

		if err := r.client.Create(ctx, profile); err != nil {
			if errors.IsAlreadyExists(err) {
				continue
			}
			return fmt.Errorf("creating operator default profile %s: %w", profile.Name, err)
		}
	}

	r.log.Info("Deploying metrics service")
	if err := r.client.Create(ctx, metricsService); err != nil {
		if errors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("creating metrics service: %w", err)
	}

	r.log.Info("Deploying operator service monitor")
	if err := r.client.Create(
		ctx, serviceMonitor,
	); err != nil {
		//nolint:gocritic
		if runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
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
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
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

	if !cfg.Spec.StaticWebhookConfig {
		r.log.Info("Updating operator webhook")
		if err := webhook.Update(ctx, r.client); err != nil {
			return fmt.Errorf("updating webhook: %w", err)
		}
	}

	r.log.Info("Updating operator daemonset")
	if err := r.client.Patch(ctx, spodInstance, client.Merge); err != nil {
		return fmt.Errorf("updating operator DaemonSet: %w", err)
	}

	r.log.Info("Updating operator default profiles")
	for _, profile := range r.defaultProfiles(cfg) {
		// Adapt the namespace if we watch only a single one
		if r.watchNamespace != "" {
			profile.Namespace = r.watchNamespace
		}

		pKey := types.NamespacedName{
			Name:      profile.GetName(),
			Namespace: profile.GetNamespace(),
		}
		foundProfile := &seccompprofileapi.SeccompProfile{}
		var err error
		if err = r.client.Get(ctx, pKey, foundProfile); err == nil {
			updatedProfile := foundProfile.DeepCopy()
			updatedProfile.Spec = *profile.Spec.DeepCopy()
			if updateErr := r.client.Update(ctx, updatedProfile); updateErr != nil {
				return fmt.Errorf("updating operator default profile %s: %w", profile.Name, updateErr)
			}
			continue
		}

		if errors.IsNotFound(err) {
			// Handle new default profile
			if createErr := r.client.Create(ctx, profile); err != nil {
				if errors.IsAlreadyExists(createErr) {
					return nil
				}
				return fmt.Errorf("creating operator default profile %s: %w", profile.Name, createErr)
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
		if runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else {
			return fmt.Errorf("updating service monitor: %w", err)
		}
	}

	return nil
}

// getConfiguredSPOd gets a fully configured SPOd instance from a desired
// configuration and the reference base SPOd.
func (r *ReconcileSPOd) getConfiguredSPOd(
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
	image string,
	pullPolicy corev1.PullPolicy,
	caInjectType bindata.CAInjectType,
) *appsv1.DaemonSet {
	newSPOd := r.baseSPOd.DeepCopy()

	newSPOd.SetName(cfg.GetName())
	newSPOd.SetNamespace(r.namespace)
	templateSpec := &newSPOd.Spec.Template.Spec

	templateSpec.InitContainers = []corev1.Container{
		r.baseSPOd.Spec.Template.Spec.InitContainers[bindata.InitContainerIDNonRootenabler],
	}
	// Set Images
	// Base workload
	templateSpec.Containers = []corev1.Container{
		r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDDaemon],
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

	// SELinux parameters
	enableSelinux := (cfg.Spec.EnableSelinux != nil && *cfg.Spec.EnableSelinux) ||
		// enable SELinux support per default in OpenShift
		(cfg.Spec.EnableSelinux == nil && caInjectType == bindata.CAInjectTypeOpenShift)

	if enableSelinux {
		templateSpec.InitContainers = append(
			templateSpec.InitContainers,
			r.baseSPOd.Spec.Template.Spec.InitContainers[bindata.InitContainerIDSelinuxSharedPoliciesCopier])
		templateSpec.Containers = append(
			templateSpec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDSelinuxd])

		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-selinux=true")
	}

	// Custom host proc volume
	useCustomHostProc := cfg.Spec.HostProcVolumePath != bindata.DefaultHostProcPath
	volume, mount := bindata.CustomHostProcVolume(cfg.Spec.HostProcVolumePath)

	// Disable profile recording controller by default
	enableRecording := false
	if isLogEnricherEnabled(cfg) || isBpfRecorderEnabled(cfg) {
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

	if isLogEnricherEnabled(cfg) {
		ctr := r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher]
		ctr.Image = image

		if useCustomHostProc {
			ctr.VolumeMounts = append(ctr.VolumeMounts, mount)
		}

		templateSpec.Containers = append(templateSpec.Containers, ctr)
		// pass the log enricher env var to the daemon as the profile recorder is otherwise disabled
		addEnvVar(templateSpec, config.EnableLogEnricherEnvKey)
	}

	// Bpf recorder parameters
	if isBpfRecorderEnabled(cfg) {
		ctr := r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDBpfRecorder]
		ctr.Image = image

		if useCustomHostProc {
			ctr.VolumeMounts = append(ctr.VolumeMounts, mount)
		}

		templateSpec.Containers = append(templateSpec.Containers, ctr)
		// pass the bpf recorder env var to the daemon as the profile recorder is otherwise disabled
		addEnvVar(templateSpec, config.EnableBpfRecorderEnvKey)
	}

	// AppArmor parameters
	if cfg.Spec.EnableAppArmor {
		falsely, truly := false, true
		var userRoot int64
		// a more privileged mode is required when apparmor is enabled
		// TODO: review security model and provide a dynamic approach that can be case specific
		templateSpec.Containers[bindata.ContainerIDDaemon].SecurityContext = &corev1.SecurityContext{
			AllowPrivilegeEscalation: &truly,
			Privileged:               &truly,
			ReadOnlyRootFilesystem:   &falsely,
			RunAsUser:                &userRoot,
			RunAsGroup:               &userRoot,
		}

		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-apparmor=true")

		// Remove AppArmor constraints to be able to manage AppArmor.
		if newSPOd.ObjectMeta.Annotations == nil {
			newSPOd.ObjectMeta.Annotations = make(map[string]string)
		}
		newSPOd.ObjectMeta.Annotations[appArmorAnnotation] = "unconfined"

		// HostPID is required for AppArmor when trying to get access to the host ns
		templateSpec.HostPID = true
	}

	// Enable memory optimization for spod controller
	if cfg.Spec.EnableMemoryOptimization {
		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-mem-optim=true")
	}

	// Metrics parameters
	templateSpec.Containers = append(
		templateSpec.Containers,
		r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDMetrics],
	)

	for i := range templateSpec.InitContainers {
		// Set image pull policy
		templateSpec.InitContainers[i].ImagePullPolicy = pullPolicy

		// Set the logging verbosity
		templateSpec.InitContainers[i].Env = append(templateSpec.InitContainers[i].Env, verbosityEnv(cfg.Spec.Verbosity))

		// Update the SELinux type tag only when AppArmor is not enabled this is to prevent a crash.
		// The SELinux type tag needs to be configured independent of EnableSelinux flag, because the
		// SELinux can be active on the node regardless if the SELinux feature is enabled or not in the operator.
		// For instance, on Flatcar Linux SELinux type tag needs to be set to 'unconfined_t' instead of 'spc_t'
		// even though SELinux is disabled in order to get the containers to start.
		if !cfg.Spec.EnableAppArmor {
			configureSeLinuxTag(templateSpec.InitContainers[i].SecurityContext, cfg.Spec.SelinuxTypeTag)
		}
	}

	for i := range templateSpec.Containers {
		// The metrics image should be pulled always as IfNotPresent
		if templateSpec.Containers[i].Name == bindata.MetricsContainerName {
			continue
		}
		// Set image pull policy
		templateSpec.Containers[i].ImagePullPolicy = pullPolicy

		// Set the logging verbosity
		templateSpec.Containers[i].Env = append(templateSpec.Containers[i].Env, verbosityEnv(cfg.Spec.Verbosity))

		// Enable profiling if requested
		if cfg.Spec.EnableProfiling {
			enableContainerProfiling(templateSpec, i)
		}
		// Update the SELinux type tag only when AppArmor is not enabled this is to prevent a crash.
		// The SELinux type tag needs to be configured independent of EnableSelinux flag, because the
		// SELinux can be active on the node regardless if the SELinux feature is enabled or not in the operator.
		// For instance, on Flatcar Linux SELinux type tag needs to be set to 'unconfined_t' instead of 'spc_t'
		// even though SELinux is disabled in order to get the containers to start.
		if !cfg.Spec.EnableAppArmor {
			configureSeLinuxTag(templateSpec.Containers[i].SecurityContext, cfg.Spec.SelinuxTypeTag)
		}
	}

	templateSpec.Tolerations = cfg.Spec.Tolerations
	templateSpec.Affinity = cfg.Spec.Affinity
	templateSpec.ImagePullSecrets = cfg.Spec.ImagePullSecrets
	templateSpec.PriorityClassName = cfg.Spec.PriorityClassName

	return newSPOd
}

func isLogEnricherEnabled(cfg *spodv1alpha1.SecurityProfilesOperatorDaemon) bool {
	enableLogEnricherEnv, err := strconv.ParseBool(os.Getenv(config.EnableLogEnricherEnvKey))
	if err != nil {
		enableLogEnricherEnv = false
	}

	return cfg.Spec.EnableLogEnricher || enableLogEnricherEnv
}

func isBpfRecorderEnabled(cfg *spodv1alpha1.SecurityProfilesOperatorDaemon) bool {
	enableBpfRecorderEnv, err := strconv.ParseBool(os.Getenv(config.EnableBpfRecorderEnvKey))
	if err != nil {
		enableBpfRecorderEnv = false
	}

	return cfg.Spec.EnableBpfRecorder || enableBpfRecorderEnv
}

func addEnvVar(templateSpec *corev1.PodSpec, envVarKey string) {
	envValue, err := strconv.ParseBool(os.Getenv(envVarKey))
	if err != nil {
		envValue = false
	}

	envVar := corev1.EnvVar{
		Name:  envVarKey,
		Value: fmt.Sprint(envValue),
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

func verbosityEnv(value uint) corev1.EnvVar {
	return corev1.EnvVar{
		Name:  config.VerbosityEnvKey,
		Value: fmt.Sprint(value),
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
			Value: fmt.Sprint(config.DefaultProfilingPort + add),
		},
	}
}

func spodNeedsUpdate(configured, found *appsv1.DaemonSet) bool {
	// If the length of the containers don't match, we clearly need an update.
	// This way we avoid the expensive DeepDerivative check.
	return (len(configured.Spec.Template.Spec.InitContainers) != len(found.Spec.Template.Spec.InitContainers) ||
		len(configured.Spec.Template.Spec.Containers) != len(found.Spec.Template.Spec.Containers) ||
		!apiequality.Semantic.DeepDerivative(configured.Spec.Template, found.Spec.Template))
}
