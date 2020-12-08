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

package selinuxpolicy

import (
	"bytes"
	"context"
	"strings"
	"text/template"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/v1alpha1"
)

// The underscore is not a valid character in a pod, so we can
// safely use it as a separator.
const policyWrapper = `(block {{.Name}}_{{.Namespace}}
    {{.Policy}}
)`

const selinuxFinalizerName = "selinuxpolicy.finalizers.selinuxpolicy.k8s.io"

// blank assignment to verify that ReconcileSelinuxPolicy implements `reconcile.Reconciler`.
var _ reconcile.Reconciler = &ReconcileSP{}

// ReconcileSP reconciles a SelinuxPolicy object.
type ReconcileSP struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver.
	client         client.Client
	scheme         *runtime.Scheme
	policyTemplate *template.Template
	record         event.Recorder
}

// Reconcile reads that state of the cluster for a SelinuxPolicy object and makes changes based on the state read
// and what is in the `SelinuxPolicy.Spec`.
func (r *ReconcileSP) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling SelinuxPolicy")

	// Fetch the SelinuxPolicy instance
	instance := &spov1alpha1.SelinuxPolicy{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		return reconcile.Result{}, IgnoreNotFound(err)
	}

	// Set up an initial state
	policyCopy := instance.DeepCopy()
	if policyCopy.Status.State == "" {
		policyCopy.Status.State = spov1alpha1.PolicyStatePending
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SelinuxPolicy status to PENDING")
		}
		return reconcile.Result{}, nil
	}

	// If "apply" is false, no need to do anything, let the deployer
	// review it.
	if !instance.Spec.Apply {
		policyCopy := instance.DeepCopy()
		policyCopy.Status.State = spov1alpha1.PolicyStatePending
		if err := r.client.Status().Update(context.TODO(), policyCopy); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "Updating SelinuxPolicy status to PENDING")
		}
		return reconcile.Result{}, nil
	}

	if instance.Status.Usage != GetPolicyUsage(instance.Name, instance.Namespace) {
		if err := r.addUsageStatus(instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	if instance.ObjectMeta.DeletionTimestamp.IsZero() {
		// The object is not being deleted
		if !SliceContainsString(instance.ObjectMeta.Finalizers, selinuxFinalizerName) {
			return r.addFinalizer(instance)
		}
		return r.reconcileConfigMap(instance, reqLogger)
	}

	// The object is being deleted
	if SliceContainsString(instance.ObjectMeta.Finalizers, selinuxFinalizerName) {
		if err := r.deleteConfigMap(instance, reqLogger); err != nil {
			return reconcile.Result{}, err
		}

		return r.removeFinalizer(instance)
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileSP) addFinalizer(sp *spov1alpha1.SelinuxPolicy) (reconcile.Result, error) {
	spcopy := sp.DeepCopy()
	spcopy.ObjectMeta.Finalizers = append(spcopy.ObjectMeta.Finalizers, selinuxFinalizerName)
	if err := r.client.Update(context.Background(), spcopy); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Adding finalizer to SelinuxPolicy")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) addUsageStatus(sp *spov1alpha1.SelinuxPolicy) error {
	spcopy := sp.DeepCopy()
	spcopy.Status.Usage = GetPolicyUsage(spcopy.Name, spcopy.Namespace)
	if err := r.client.Status().Update(context.Background(), spcopy); err != nil {
		return errors.Wrap(err, "Updating SelinuxPolicy usage status")
	}
	return nil
}

func (r *ReconcileSP) removeFinalizer(sp *spov1alpha1.SelinuxPolicy) (reconcile.Result, error) {
	spcopy := sp.DeepCopy()
	spcopy.ObjectMeta.Finalizers = RemoveStringFromSlice(spcopy.ObjectMeta.Finalizers, selinuxFinalizerName)
	if err := r.client.Update(context.Background(), spcopy); err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Removing SelinuxPolicy finalizer")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) reconcileConfigMap(sp *spov1alpha1.SelinuxPolicy, l logr.Logger) (reconcile.Result, error) {
	// Define a new ConfigMap object
	cm := r.newConfigMapForPolicy(sp)

	// Check if this cm already exists
	foundCM := &corev1.ConfigMap{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, foundCM)
	if err != nil && kerrors.IsNotFound(err) {
		l.Info("Creating a new ConfigMap", "ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
		if err = r.client.Create(context.TODO(), cm); err != nil {
			return reconcile.Result{}, IgnoreAlreadyExists(err)
		}

		// CM created successfully - don't requeue
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, errors.Wrap(err, "Getting SelinuxPolicy ConfigMap")
	}
	return reconcile.Result{}, nil
}

func (r *ReconcileSP) deleteConfigMap(instance *spov1alpha1.SelinuxPolicy, logger logr.Logger) error {
	// Define a new ConfigMap object
	cm := r.newConfigMapForPolicy(instance)
	logger.Info("Deleting ConfigMap", "ConfigMap.Namespace", cm.Namespace, "ConfigMap.Name", cm.Name)
	return IgnoreNotFound(r.client.Delete(context.TODO(), cm))
}

func (r *ReconcileSP) newConfigMapForPolicy(cr *spov1alpha1.SelinuxPolicy) *corev1.ConfigMap {
	labels := map[string]string{
		// TODO(jaosorior): Use constant
		cmIsSelinuxPolicy: "true",
		"appName":         cr.Name,
		"appNamespace":    cr.Namespace,
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      GetPolicyConfigMapName(cr.Name, cr.Namespace),
			Namespace: GetOperatorNamespace(),
			Labels:    labels,
		},
		Data: map[string]string{
			GetPolicyName(cr.Name, cr.Namespace) + ".cil": r.wrapPolicy(cr),
		},
	}
}

func (r *ReconcileSP) wrapPolicy(cr *spov1alpha1.SelinuxPolicy) string {
	parsedpolicy := strings.TrimSpace(cr.Spec.Policy)
	// ident
	parsedpolicy = strings.ReplaceAll(parsedpolicy, "\n", "\n    ")
	// replace empty lines
	parsedpolicy = strings.TrimSpace(parsedpolicy)
	data := struct {
		Name      string
		Namespace string
		Policy    string
	}{
		Name:      cr.Name,
		Namespace: cr.Namespace,
		Policy:    parsedpolicy,
	}
	var result bytes.Buffer
	if err := r.policyTemplate.Execute(&result, data); err != nil {
		log.Error(err, "Couldn't render policy", "SelinuxPolicy.Name", cr.GetName())
	}
	return result.String()
}
