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

package spod

import (
	"context"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/spod/bindata"
)

// TODO(jaosorior): Use better method than a label constant.
const cmIsSPOdConfig = "security-profiles-operator/config"

// DaemonTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type DaemonTunables struct {
	NonRootEnablerImage string
	SelinuxdImage       string
	LogEnricherImage    string
	WatchNamespace      string
}

// Setup adds a controller that reconciles the SPOd DaemonSet.
func Setup(ctx context.Context, mgr ctrl.Manager, dt *DaemonTunables, l logr.Logger) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("spod-config").
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(isSPOdConfig)).
		Owns(&appsv1.DaemonSet{}).
		Complete(&ReconcileSPOd{
			baseSPOd:       getEffectiveSPOd(dt),
			client:         mgr.GetClient(),
			log:            l,
			record:         event.NewAPIRecorder(mgr.GetEventRecorderFor("spod-config")),
			scheme:         mgr.GetScheme(),
			watchNamespace: dt.WatchNamespace,
		})
}

func getEffectiveSPOd(dt *DaemonTunables) *appsv1.DaemonSet {
	refSPOd := bindata.Manifest.DeepCopy()

	daemon := &refSPOd.Spec.Template.Spec.Containers[0]
	if dt.WatchNamespace != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.RestrictNamespaceEnvKey,
			Value: dt.WatchNamespace,
		})
	}

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[1]
	selinuxd.Image = dt.SelinuxdImage

	logEnricher := &refSPOd.Spec.Template.Spec.Containers[2]
	logEnricher.Image = dt.LogEnricherImage

	initcnt := &refSPOd.Spec.Template.Spec.InitContainers[0]
	initcnt.Image = dt.NonRootEnablerImage
	sepolImage := &refSPOd.Spec.Template.Spec.InitContainers[1]
	sepolImage.Image = dt.SelinuxdImage // selinuxd ships the policies as well
	return refSPOd
}

func isSPOdConfig(obj runtime.Object) bool {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}
	// we only care about this namespace
	if cm.GetNamespace() != config.GetOperatorNamespace() {
		return false
	}
	if cm.GetName() != "config" {
		return false
	}
	labels := cm.GetLabels()
	if labels == nil {
		return false
	}
	_, ok = labels[cmIsSPOdConfig]
	return ok
}
