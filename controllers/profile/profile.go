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

package profile

import (
	"context"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	// default reconcile timeout
	reconcileTimeout = 1 * time.Minute

	longWait = 1 * time.Minute

	errGetProfile = "cannot get profile"
)

// SeccompProfileAnnotation is the annotation on a ConfigMap that specifies its
// intention to be treated as a seccomp profile.
const SeccompProfileAnnotation = "seccomp.security.kubernetes.io/profile"

// isProfile checks if a ConfigMap has been designated as a seccomp profile.
func isProfile(obj runtime.Object) bool {
	r, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}

	return r.Annotations[SeccompProfileAnnotation] == "true"
}

// Setup adds a controller that reconciles seccomp profiles.
func Setup(mgr ctrl.Manager, l logr.Logger) error {
	name := "profile"

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(isProfile)).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
		})
}

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
}

// Reconcile reconciles a ConfigMap representing a seccomp profile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	profile := &corev1.ConfigMap{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, profile); err != nil {
		// Returning an error means we will be requeued implicitly.
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}

	logger.Info("Reconciled profile", "resource version", profile.GetResourceVersion())
	return reconcile.Result{RequeueAfter: longWait}, nil
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}
