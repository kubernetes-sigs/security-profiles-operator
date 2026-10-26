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

package common

import (
	"context"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

// ReleaseController releases the profiles of a kind which the SPOD disabled
// when they get deleted. Only the controller of a kind removes the finalizer
// of its node from a profile, so without it the deletion of a profile which
// the node installed while the kind was enabled would wait for the node to
// go away. Nothing gets removed from the node: the files and policies of the
// profile stay where the kind installed them, like on a node which does not
// support the kind anymore, see ReleaseUnsupported.
type ReleaseController struct {
	name          string
	newProfile    func() profilebase.SecurityProfileBase
	schemeBuilder runtime.SchemeBuilder

	client   client.Client
	reader   client.Reader
	log      logr.Logger
	nodeName string

	// written keeps the node status states this node wrote.
	written nodestatus.WrittenStates
}

// NewReleaseController returns the controller which releases the deleted
// profiles of a disabled kind. name is the name of the controller of the
// kind, newProfile returns an empty profile of the kind.
func NewReleaseController(
	name string,
	newProfile func() profilebase.SecurityProfileBase,
	schemeBuilder runtime.SchemeBuilder,
) *ReleaseController {
	return &ReleaseController{
		name:          name + "-release",
		newProfile:    newProfile,
		schemeBuilder: schemeBuilder,
	}
}

// Name returns the name of the controller.
func (r *ReleaseController) Name() string {
	return r.name
}

// SchemeBuilder returns the API scheme of the controller.
func (r *ReleaseController) SchemeBuilder() runtime.SchemeBuilder {
	return r.schemeBuilder
}

// Setup adds the controller to the manager. Only the profiles which are
// being deleted get reconciled.
func (r *ReleaseController) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(r.name)
	r.nodeName = os.Getenv(config.NodeNameEnvKey)

	return ctrl.NewControllerManagedBy(mgr).
		Named(r.name).
		For(r.newProfile(), builder.WithPredicates(predicate.NewPredicateFuncs(
			func(obj client.Object) bool { return !obj.GetDeletionTimestamp().IsZero() },
		))).
		Complete(r)
}

// Reconcile releases a deleted profile of the disabled kind.
func (r *ReleaseController) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	profile := r.newProfile()
	if found, err := GetProfile(ctx, r.client, req.NamespacedName, profile); !found {
		if err == nil {
			r.written.Forget(req.NamespacedName)
		}

		return reconcile.Result{}, err
	}

	if profile.GetDeletionTimestamp().IsZero() {
		return reconcile.Result{}, nil
	}

	r.log.V(config.VerboseLevel).Info("Releasing the deleted profile of a disabled kind",
		"profile", req.Name, "namespace", req.Namespace)

	return reconcile.Result{}, ReleaseUnsupported(
		ctx, r.client, r.reader, profile, r.nodeName, &r.written,
	)
}
