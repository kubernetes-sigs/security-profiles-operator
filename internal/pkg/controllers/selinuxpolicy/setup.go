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
	"context"
	"text/template"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spov1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var log = logf.Log.WithName("selinuxpolicy")

// TODO(jaosorior): Use better method than a label constant.
const cmIsSelinuxPolicy = "is-selinux-policy"

// Setup adds a controller that reconciles seccomp profiles.
func Setup(ctx context.Context, mgr ctrl.Manager, l logr.Logger) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("configmaps").
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(hasSELinuxLabel)).
		Owns(&corev1.Pod{}).
		Complete(&ReconcileConfigMap{
			client: mgr.GetClient(),
			scheme: mgr.GetScheme(),
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("configmaps")),
		}); err != nil {
		return errors.Wrap(err, "creating configmap controller")
	}

	// Create template to wrap policies
	tmpl, err := template.New("policyWrapper").Parse(policyWrapper)
	if err != nil {
		return errors.Wrap(err, "creating policy wrapper template")
	}
	// Register the regular reconciler to manage SelinuxPolicies
	return ctrl.NewControllerManagedBy(mgr).
		Named("profile").
		For(&spov1alpha1.SelinuxPolicy{}).
		Complete(&ReconcileSP{
			client:         mgr.GetClient(),
			scheme:         mgr.GetScheme(),
			policyTemplate: tmpl,
			record:         event.NewAPIRecorder(mgr.GetEventRecorderFor("selinuxpolicy")),
		})
}

func hasSELinuxLabel(obj runtime.Object) bool {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}
	// we only care about this namespace
	if cm.GetNamespace() != config.GetOperatorNamespace() {
		return false
	}
	labels := cm.GetLabels()
	if labels == nil {
		return false
	}
	val, ok := labels[cmIsSelinuxPolicy]
	if !ok {
		return false
	}
	return val == "true"
}
