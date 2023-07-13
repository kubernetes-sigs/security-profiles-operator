/*
Copyright 2021 The Kubernetes Authors.

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

package nodestatus

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *StatusReconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = mgr.GetEventRecorderFor(r.Name())

	// Register a special reconciler for status events
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}).
		Complete(r)
}
