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

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

func (r *BindingTrackerReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	const name = "binding-tracker"

	r.client = mgr.GetClient()
	r.reader = mgr.GetAPIReader()
	r.log = ctrl.Log.WithName(name)

	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&profilebindingapi.ProfileBinding{},
		linkedPodsKey,
		func(rawObj client.Object) []string {
			pb, ok := rawObj.(*profilebindingapi.ProfileBinding)
			if !ok {
				return []string{}
			}

			return pb.Status.ActiveWorkloads
		},
	); err != nil {
		return fmt.Errorf("creating profile binding index: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.Pod{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc: func(_ event.CreateEvent) bool { return true },
			DeleteFunc: func(_ event.DeleteEvent) bool { return true },
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !reflect.DeepEqual(e.ObjectOld.GetLabels(), e.ObjectNew.GetLabels())
			},
			GenericFunc: func(_ event.GenericEvent) bool { return true },
		}).
		Complete(r)
}
