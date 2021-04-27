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

package selinuxprofile

import (
	"context"
	"text/template"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/metrics"
)

var log = logf.Log.WithName("selinuxprofile")

// Setup adds a controller that reconciles seccomp profiles.
func Setup(ctx context.Context, mgr ctrl.Manager, l logr.Logger, met *metrics.Metrics) error {
	// Create template to wrap policies
	tmpl, err := template.New("profileWrapper").Parse(profileWrapper)
	if err != nil {
		return errors.Wrap(err, "creating profile wrapper template")
	}
	// Register the regular reconciler to manage SelinuxProfiles
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&spov1alpha1.SelinuxProfile{}).
		Complete(&ReconcileSP{
			client:         mgr.GetClient(),
			scheme:         mgr.GetScheme(),
			policyTemplate: tmpl,
			record:         event.NewAPIRecorder(mgr.GetEventRecorderFor("selinuxprofile")),
		})
}
