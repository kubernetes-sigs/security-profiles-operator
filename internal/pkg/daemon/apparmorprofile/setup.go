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

package apparmorprofile

import (
	"context"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// Setup adds a controller that reconciles AppArmor profiles.
func (r *Reconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = event.NewAPIRecorder(mgr.GetEventRecorderFor("apparmorprofile"))
	r.metrics = met
	r.manager = NewAppArmorProfileManager(r.log)

	r.logNodeInfo()

	// Register the regular reconciler to manage AppArmorProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("apparmorprofile").
		For(&v1alpha1.AppArmorProfile{}).
		Complete(r)
}
