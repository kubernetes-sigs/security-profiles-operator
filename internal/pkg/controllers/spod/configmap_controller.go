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
	"strconv"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// blank assignment to verify that ReconcileConfigMap implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSPOd{}

// ReconcileSPOd reconciles the SPOd DaemonSet object.
type ReconcileSPOd struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	baseSPOd *appsv1.DaemonSet
	record   event.Recorder
	log      logr.Logger
}

// Reconcile reads that state of the cluster for a ConfigMap object and makes changes based on the state read
// and what is in the `ConfigMap.Spec`.
func (r *ReconcileSPOd) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	// Fetch the ConfigMap instance
	cminstance := &corev1.ConfigMap{}
	if err := r.client.Get(ctx, request.NamespacedName, cminstance); err != nil {
		if kerrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error getting spod configuration: %w", err)
	}
	spodKey := types.NamespacedName{
		Name:      r.baseSPOd.GetName(),
		Namespace: config.GetOperatorNamespace(),
	}
	foundSPOd := &appsv1.DaemonSet{}
	if getErr := r.client.Get(ctx, spodKey, foundSPOd); getErr != nil {
		if kerrors.IsNotFound(getErr) {
			return r.handleCreate(ctx, cminstance)
		}
		return reconcile.Result{}, fmt.Errorf("error getting spod DaemonSet: %w", getErr)
	}

	// NOTE(jaosorior): We gotta handle updates
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) handleCreate(ctx context.Context, cfg *corev1.ConfigMap) (reconcile.Result, error) {
	r.log.Info("Creating SPOd")
	newSPOd := r.getConfiguredSPOd(cfg)

	if err := controllerutil.SetControllerReference(cfg, newSPOd, r.scheme); err != nil {
		return reconcile.Result{}, fmt.Errorf("error setting spod controller reference: %w", err)
	}

	if createErr := r.client.Create(ctx, newSPOd); createErr != nil {
		if kerrors.IsAlreadyExists(createErr) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, fmt.Errorf("error creating spod DaemonSet: %w", createErr)
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSPOd) getConfiguredSPOd(cfg *corev1.ConfigMap) *appsv1.DaemonSet {
	newSPOd := r.baseSPOd.DeepCopy()

	newSPOd.Spec.Template.Spec.Containers = []corev1.Container{r.baseSPOd.Spec.Template.Spec.Containers[0]}

	enableSelinux, err := strconv.ParseBool(cfg.Data[config.SPOcEnableSelinux])
	if err == nil && enableSelinux {
		newSPOd.Spec.Template.Spec.Containers = append(
			newSPOd.Spec.Template.Spec.Containers,
			r.baseSPOd.Spec.Template.Spec.Containers[1])

		newSPOd.Spec.Template.Spec.Containers[0].Args = append(
			newSPOd.Spec.Template.Spec.Containers[0].Args,
			"--with-selinux=true")
	}

	imagePullPolicyStr, found := cfg.Data[config.SPOdImagePullPolicy]
	if found {
		pullPolicy := corev1.PullPolicy(imagePullPolicyStr)
		for i := range newSPOd.Spec.Template.Spec.Containers {
			newSPOd.Spec.Template.Spec.Containers[i].ImagePullPolicy = pullPolicy
		}
	}

	return newSPOd
}
