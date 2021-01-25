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
	"sync"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/spod/bindata"
)

// TODO(jaosorior): Use better method than a label constant.
const cmIsSPOdConfig = "security-profiles-operator/config"

// SPOdTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type DaemonTunables struct {
	DaemonImage         string
	NonRootEnablerImage string
	SelinuxdImage       string
	WatchNamespace      string
}

var (
	operatorNamespace string
	mutex             = &sync.Mutex{}
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func Setup(ctx context.Context, mgr ctrl.Manager, dt *DaemonTunables, l logr.Logger) (err error) {
	mutex.Lock()
	if operatorNamespace, err = config.GetOperatorNamespace(); err != nil {
		return errors.Wrap(err, "getting operator namespace")
	}
	mutex.Unlock()

	return ctrl.NewControllerManagedBy(mgr).
		Named("spod-config").
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(isSPOdConfig)).
		Owns(&appsv1.DaemonSet{}).
		Complete(&ReconcileSPOd{
			baseSPOd: getEffectiveSPOd(dt),
			client:   mgr.GetClient(),
			log:      l,
			record:   event.NewAPIRecorder(mgr.GetEventRecorderFor("spod-config")),
			scheme:   mgr.GetScheme(),
		})
}

func getEffectiveSPOd(dt *DaemonTunables) *appsv1.DaemonSet {
	refSPOd := bindata.Manifest.DeepCopy()

	daemon := &refSPOd.Spec.Template.Spec.Containers[0]
	daemon.Image = dt.DaemonImage
	if dt.WatchNamespace != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.RestrictNamespaceEnvKey,
			Value: dt.WatchNamespace,
		})
	}

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[1]
	selinuxd.Image = dt.SelinuxdImage

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
	// we only care about this operatorNamespace
	mutex.Lock()
	if cm.GetNamespace() != operatorNamespace {
		return false
	}
	mutex.Unlock()
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
