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

package apparmorprofile

import (
	"context"
	"os"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Setup adds a controller that reconciles AppArmor profiles.
func (r *Reconciler) Setup(
	_ context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, "apparmorprofile")
	r.metrics = met
	r.manager = NewAppArmorProfileManager(r.log)
	r.nodeName = os.Getenv(config.NodeNameEnvKey)

	r.logNodeInfo()

	if r.manager.Enabled() {
		removeStaleTempFiles(r.log)
	}

	// Register the regular reconciler to manage AppArmorProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("apparmorprofile").
		// The periodic resyncs pass to load a profile again which got
		// unloaded or whose policy file got changed on the host. Loading an
		// unchanged profile which is still loaded neither writes its file
		// nor runs apparmor_parser.
		For(&apparmorprofileapi.AppArmorProfile{}, builder.WithPredicates(predicate.Or(
			predicate.GenerationChangedPredicate{},
			predicate.LabelChangedPredicate{},
			common.ResyncPredicate,
		))).
		Complete(r)
}
