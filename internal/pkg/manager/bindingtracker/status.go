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

package bindingtracker

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/api/common"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	// missingProfileRetry is the time after which a binding to a missing
	// profile is checked again.
	missingProfileRetry = time.Minute

	// profileRefKey indexes bindings by the profile they refer to.
	profileRefKey = ".spec.profileRef"
)

// bindingStatusReconciler reports on the Ready condition of a ProfileBinding
// whether the profile it refers to exists. The binding webhook skips bindings
// to missing profiles, so this is the only place where the user can see it.
type bindingStatusReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
}

// profileRefValue returns the value of the profile reference index.
func profileRefValue(kind profilebindingapi.ProfileBindingKind, name string) string {
	return string(kind) + "/" + name
}

func profileRefIndex(obj client.Object) []string {
	binding, ok := obj.(*profilebindingapi.ProfileBinding)
	if !ok {
		return nil
	}

	return []string{profileRefValue(binding.Spec.ProfileRef.Kind, binding.Spec.ProfileRef.Name)}
}

// bindingRequests returns a map function which enqueues the bindings which
// refer to a profile of the provided kind.
func (r *bindingStatusReconciler) bindingRequests(
	kind profilebindingapi.ProfileBindingKind,
) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		bindings := &profilebindingapi.ProfileBindingList{}
		if err := r.client.List(ctx, bindings, client.MatchingFields{
			profileRefKey: profileRefValue(kind, obj.GetName()),
		}); err != nil {
			r.log.Error(err, "cannot list bindings of profile", "profile", obj.GetName())

			return nil
		}

		requests := make([]reconcile.Request, 0, len(bindings.Items))
		for i := range bindings.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&bindings.Items[i]),
			})
		}

		return requests
	}
}

func (r *bindingStatusReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	binding := &profilebindingapi.ProfileBinding{}
	if err := r.client.Get(ctx, req.NamespacedName, binding); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	found, err := r.profileExists(ctx, binding.Spec.ProfileRef)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("looking up profile of binding: %w", err)
	}

	condition := common.Available()
	res := reconcile.Result{}

	if !found {
		condition = common.Unavailable(fmt.Sprintf(
			"%s %s not found", binding.Spec.ProfileRef.Kind, binding.Spec.ProfileRef.Name,
		))
		res.RequeueAfter = missingProfileRetry
	}

	if err := r.setCondition(ctx, req, &condition); err != nil {
		return reconcile.Result{}, err
	}

	return res, nil
}

func (r *bindingStatusReconciler) profileExists(
	ctx context.Context, ref profilebindingapi.ProfileRef,
) (bool, error) {
	var profile client.Object

	switch ref.Kind {
	case profilebindingapi.ProfileBindingKindSeccompProfile:
		profile = &seccompprofileapi.SeccompProfile{}
	case profilebindingapi.ProfileBindingKindSelinuxProfile:
		profile = &selinuxprofileapi.SelinuxProfile{}
	case profilebindingapi.ProfileBindingKindAppArmorProfile:
		profile = &apparmorprofileapi.AppArmorProfile{}
	default:
		return false, nil
	}

	if err := r.client.Get(ctx, util.NamespacedName(ref.Name, ""), profile); err != nil {
		return false, client.IgnoreNotFound(err)
	}

	return true, nil
}

func (r *bindingStatusReconciler) setCondition(
	ctx context.Context, req reconcile.Request, condition *metav1.Condition,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		binding := &profilebindingapi.ProfileBinding{}
		if err := r.reader.Get(ctx, req.NamespacedName, binding); err != nil {
			return client.IgnoreNotFound(err)
		}

		updated := binding.DeepCopy()
		updated.Status.SetConditionForGeneration(condition, binding.GetGeneration())

		if reflect.DeepEqual(binding.Status, updated.Status) {
			return nil
		}

		r.log.V(config.VerboseLevel).
			Info("Updating binding condition", "binding", req.NamespacedName,
				"reason", condition.Reason)

		if err := r.client.Status().Update(ctx, updated); err != nil {
			return fmt.Errorf("updating binding status: %w", err)
		}

		return nil
	})
}
