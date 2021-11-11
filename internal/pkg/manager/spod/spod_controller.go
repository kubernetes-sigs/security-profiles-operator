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

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	sccmpv1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	reasonCannotCreateSPOD event.Reason = "CannotCreateSPOD"
	reasonCannotUpdateSPOD event.Reason = "CannotUpdateSPOD"
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
	client         client.Client
	scheme         *runtime.Scheme
	baseSPOd       *appsv1.DaemonSet
	record         event.Recorder
	log            logr.Logger
	watchNamespace string
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
// nolint:lll
//
// Used for leader election:
// +kubebuilder:rbac:groups=core,resources=configmaps;events,verbs=get;list;watch;create;update;patch
//
// Operand:
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=apps,resources=daemonsets/finalizers,verbs=delete;get;update;patch
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

// Reconcile reads that state of the cluster for a SPOD object and makes changes based on the state read
// and what is in the `ConfigMap.Spec`.
func (r *ReconcileSPOd) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)
	// Fetch the ConfigMap instance
	spod := &spodv1alpha1.SecurityProfilesOperatorDaemon{}
	if err := r.client.Get(ctx, req.NamespacedName, spod); err != nil {
		if kerrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, errors.Wrap(err, "getting spod configuration")
	}

	if spod.Status.State == "" {
		return r.handleInitialStatus(ctx, spod, logger)
	}

	deploymentKey := types.NamespacedName{
		Name:      config.OperatorName,
		Namespace: config.GetOperatorNamespace(),
	}
	foundDeployment := &appsv1.Deployment{}
	if err := r.client.Get(ctx, deploymentKey, foundDeployment); err != nil {
		if kerrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error getting operator deployment: %w", err)
	}
	// We use the same target image for the deamonset as which we have right
	// now running.
	image := foundDeployment.Spec.Template.Spec.Containers[0].Image
	pullPolicy := foundDeployment.Spec.Template.Spec.Containers[0].ImagePullPolicy

	configuredSPOd := r.getConfiguredSPOd(spod, image, pullPolicy)

	spodKey := types.NamespacedName{
		Name:      spod.GetName(),
		Namespace: config.GetOperatorNamespace(),
	}

	foundSPOd := &appsv1.DaemonSet{}
	if err := r.client.Get(ctx, spodKey, foundSPOd); err != nil {
		if kerrors.IsNotFound(err) {
			createErr := r.handleCreate(ctx, spod, configuredSPOd)
			if createErr != nil {
				r.record.Event(spod, event.Warning(reasonCannotCreateSPOD, createErr))
				return reconcile.Result{}, createErr
			}
			return r.handleCreatingStatus(ctx, spod, logger)
		}
		return reconcile.Result{}, errors.Wrap(err, "getting spod DaemonSet")
	}

	if spodNeedsUpdate(configuredSPOd, foundSPOd) {
		updatedSPod := foundSPOd.DeepCopy()
		updatedSPod.Spec.Template = configuredSPOd.Spec.Template
		updateErr := r.handleUpdate(ctx, updatedSPod)
		if updateErr != nil {
			r.record.Event(spod, event.Warning(reasonCannotUpdateSPOD, updateErr))
			return reconcile.Result{}, updateErr
		}
		return r.handleUpdatingStatus(ctx, spod, logger)
	}

	if foundSPOd.Status.NumberReady == foundSPOd.Status.DesiredNumberScheduled {
		condready := spod.Status.GetCondition("Ready")
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
		return reconcile.Result{}, errors.Wrap(updateErr, "updating spod initial status")
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
		return reconcile.Result{}, errors.Wrap(updateErr, "updating spod status to creating")
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
		return reconcile.Result{}, errors.Wrap(updateErr, "updating spod status to 'updating'")
	}
	return reconcile.Result{}, nil
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
		return reconcile.Result{}, errors.Wrap(updateErr, "updating spod status to running")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleCreate(
	ctx context.Context,
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
	newSPOd *appsv1.DaemonSet,
) error {
	r.log.Info("Creating operator resources")

	if err := controllerutil.SetControllerReference(cfg, newSPOd, r.scheme); err != nil {
		return errors.Wrap(err, "setting spod controller reference")
	}

	r.log.Info("Deploying operator daemonset")
	if err := r.client.Create(ctx, newSPOd); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return nil
		}
		return errors.Wrap(err, "creating operator DaemonSet")
	}

	r.log.Info("Deploying operator default profiles")
	for _, profile := range bindata.DefaultProfiles() {
		// Adapt the namespace if we watch only a single one
		if r.watchNamespace != "" {
			profile.Namespace = r.watchNamespace
		}

		if err := r.client.Create(ctx, profile); err != nil {
			if kerrors.IsAlreadyExists(err) {
				continue
			}
			return errors.Wrapf(
				err, "creating operator default profile %s", profile.Name,
			)
		}
	}

	r.log.Info("Deploying operator service monitor")
	if err := r.client.Create(
		ctx, bindata.ServiceMonitor(),
	); err != nil {
		// nolint: gocritic
		if runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else if kerrors.IsAlreadyExists(err) {
			r.log.Info("Service monitor already exist, skipping")
		} else {
			return errors.Wrap(err, "creating service monitor")
		}
	}

	return nil
}

func (r *ReconcileSPOd) handleUpdate(
	ctx context.Context,
	spodInstance *appsv1.DaemonSet,
) error {
	r.log.Info("Updating operator daemonset")
	if err := r.client.Patch(ctx, spodInstance, client.Merge); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return nil
		}
		return errors.Wrap(err, "creating operator DaemonSet")
	}

	r.log.Info("Updating operator default profiles")
	for _, profile := range bindata.DefaultProfiles() {
		// Adapt the namespace if we watch only a single one
		if r.watchNamespace != "" {
			profile.Namespace = r.watchNamespace
		}

		pKey := types.NamespacedName{
			Name:      profile.GetName(),
			Namespace: profile.GetNamespace(),
		}
		foundProfile := &sccmpv1alpha1.SeccompProfile{}
		var err error
		if err = r.client.Get(ctx, pKey, foundProfile); err == nil {
			updatedProfile := foundProfile.DeepCopy()
			updatedProfile.Spec = *profile.Spec.DeepCopy()
			if updateErr := r.client.Update(ctx, updatedProfile); updateErr != nil {
				return errors.Wrapf(
					updateErr, "updating operator default profile %s", profile.Name,
				)
			}
			continue
		}

		if kerrors.IsNotFound(err) {
			// Handle new default profile
			if createErr := r.client.Create(ctx, profile); err != nil {
				if kerrors.IsAlreadyExists(createErr) {
					return nil
				}
				return errors.Wrapf(
					createErr, "creating operator default profile %s", profile.Name,
				)
			}
			continue
		}

		return errors.Wrapf(
			err, "getting operator default profile %s", profile.Name,
		)
	}

	r.log.Info("Updating operator service monitor")
	if err := r.client.Patch(
		ctx, bindata.ServiceMonitor(), client.Merge,
	); err != nil {
		// nolint: gocritic
		if runtime.IsNotRegisteredError(err) || meta.IsNoMatchError(err) {
			r.log.Info("Service monitor resource does not seem to exist, ignoring")
		} else if kerrors.IsAlreadyExists(err) {
			r.log.Info("Service monitor already exist, skipping")
		} else {
			return errors.Wrap(err, "updating service monitor")
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
) *appsv1.DaemonSet {
	newSPOd := r.baseSPOd.DeepCopy()

	newSPOd.SetName(cfg.GetName())
	newSPOd.SetNamespace(config.GetOperatorNamespace())
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

	// SELinux parameters
	if cfg.Spec.EnableSelinux {
		templateSpec.InitContainers = append(
			templateSpec.InitContainers,
			r.baseSPOd.Spec.Template.Spec.InitContainers[bindata.ContainerIDSelinuxd])
		templateSpec.Containers = append(
			templateSpec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDSelinuxd])

		templateSpec.Containers[bindata.ContainerIDDaemon].Args = append(
			templateSpec.Containers[bindata.ContainerIDDaemon].Args,
			"--with-selinux=true")
	}

	// Log enricher parameters
	if cfg.Spec.EnableLogEnricher {
		r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher].Image = image
		templateSpec.Containers = append(
			templateSpec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher])

		// HostPID is only required for the log-enricher
		// and is used to access cgroup files to map Process IDs to Pod IDs
		templateSpec.HostPID = true
	}

	// Bpf recorder parameters
	if cfg.Spec.EnableBpfRecorder {
		r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDBpfRecorder].Image = image
		templateSpec.Containers = append(
			templateSpec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDBpfRecorder])

		// HostPID is only required for the bpf recorder and is used to access
		// cgroup files to map Process IDs to Pod IDs.
		templateSpec.HostPID = true
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
	}

	for i := range templateSpec.Containers {
		// The metrics image should be pulled always as IfNotPresent
		if templateSpec.Containers[i].Image == bindata.MetricsImage {
			continue
		}
		// Set image pull policy
		templateSpec.Containers[i].ImagePullPolicy = pullPolicy

		// Set the logging verbosity
		templateSpec.Containers[i].Env = append(templateSpec.Containers[i].Env, verbosityEnv(cfg.Spec.Verbosity))
	}

	templateSpec.Tolerations = cfg.Spec.Tolerations

	return newSPOd
}

func verbosityEnv(value uint) corev1.EnvVar {
	return corev1.EnvVar{
		Name:  config.VerbosityEnvKey,
		Value: fmt.Sprint(value),
	}
}

func spodNeedsUpdate(configured, found *appsv1.DaemonSet) bool {
	// If the length of the containers don't match, we clearly need an update.
	// This way we avoid the expensive DeepDerivative check.
	return (len(configured.Spec.Template.Spec.InitContainers) != len(found.Spec.Template.Spec.InitContainers) ||
		len(configured.Spec.Template.Spec.Containers) != len(found.Spec.Template.Spec.Containers) ||
		!apiequality.Semantic.DeepDerivative(configured.Spec.Template, found.Spec.Template))
}
