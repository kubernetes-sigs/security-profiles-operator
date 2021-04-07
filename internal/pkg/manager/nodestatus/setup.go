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

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"

	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func Setup(ctx context.Context, mgr ctrl.Manager, l logr.Logger) error {
	// Register a special reconciler for status events
	return ctrl.NewControllerManagedBy(mgr).
		Named("nodestatus").
		For(&secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}).
		Complete(NewStatusReconciler(mgr.GetClient(),
			l,
			event.NewAPIRecorder(mgr.GetEventRecorderFor("nodestatus"))),
		)
}
