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

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	reasonCannotCreateSPOD event.Reason = "CannotCreateSPOD"
)

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

// Security Profiles Operator RBAC permissions to manage its own configuration
// nolint:lll
//
// Used for leader election:
// +kubebuilder:rbac:groups=core,namespace="security-profiles-operator",resources=configmaps;events,verbs=get;list;watch;create;update;patch
//
// Operand:
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=daemonsets/finalizers,verbs=delete;get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=securityprofilesoperatordaemons/finalizers,verbs=delete;get;update;patch
// Helpers:
// +kubebuilder:rbac:groups=apps,namespace="security-profiles-operator",resources=deployments,verbs=get;list;watch;
// +kubebuilder:rbac:groups=coordination.k8s.io,namespace="security-profiles-operator",resources=leases,verbs=create;get;update;
//
// Needed for default profiles:
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch
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

	spodKey := types.NamespacedName{
		Name:      spod.GetName(),
		Namespace: config.GetOperatorNamespace(),
	}
	foundSPOd := &appsv1.DaemonSet{}
	if err := r.client.Get(ctx, spodKey, foundSPOd); err != nil {
		if kerrors.IsNotFound(err) {
			createErr := r.handleCreate(ctx, spod, image, pullPolicy)
			if createErr != nil {
				r.record.Event(spod, event.Warning(reasonCannotCreateSPOD, createErr))
				return reconcile.Result{}, createErr
			}
			return r.handleCreatingStatus(ctx, spod, logger)
		}
		return reconcile.Result{}, errors.Wrap(err, "getting spod DaemonSet")
	}

	// NOTE(jaosorior): We gotta handle updates

	if foundSPOd.Status.NumberReady == foundSPOd.Status.DesiredNumberScheduled {
		return r.handleRunningStatus(ctx, spod, logger)
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
	image string,
	pullPolicy corev1.PullPolicy,
) error {
	r.log.Info("Creating operator resources")
	newSPOd := r.getConfiguredSPOd(cfg, image, pullPolicy)

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
				return nil
			}
			return errors.Wrapf(
				err, "creating operator default profile %s", profile.Name,
			)
		}
	}

	return nil
}

func (r *ReconcileSPOd) getConfiguredSPOd(
	cfg *spodv1alpha1.SecurityProfilesOperatorDaemon,
	image string,
	pullPolicy corev1.PullPolicy,
) *appsv1.DaemonSet {
	newSPOd := r.baseSPOd.DeepCopy()
	newSPOd.SetName(cfg.GetName())
	templateSpec := &newSPOd.Spec.Template.Spec

	// Set Images
	// - Base workload
	templateSpec.Containers = []corev1.Container{r.baseSPOd.Spec.Template.Spec.Containers[0]}
	templateSpec.Containers[0].Image = image

	// - The non root enabler
	templateSpec.InitContainers[0].Image = image

	// SELinux parameters
	if cfg.Spec.EnableSelinux {
		templateSpec.Containers = append(
			templateSpec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[1])

		templateSpec.Containers[0].Args = append(
			templateSpec.Containers[0].Args,
			"--with-selinux=true")
	}

	// Log enricher parameters
	if cfg.Spec.EnableLogEnricher {
		r.baseSPOd.Spec.Template.Spec.Containers[2].Image = image
		newSPOd.Spec.Template.Spec.Containers = append(
			newSPOd.Spec.Template.Spec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[2])

		// HostPID is only required for the log-enricher
		// and is used to access cgroup files to map Process IDs to Pod IDs
		newSPOd.Spec.Template.Spec.HostPID = true
	}

	// Set image pull policy
	for i := range templateSpec.InitContainers {
		templateSpec.InitContainers[i].ImagePullPolicy = pullPolicy
	}

	for i := range templateSpec.Containers {
		templateSpec.Containers[i].ImagePullPolicy = pullPolicy
	}

	templateSpec.Tolerations = cfg.Spec.Tolerations

	return newSPOd
}
