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
	"os"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	selinux "github.com/opencontainers/selinux/go-selinux"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	selinuxdImageKey string = "RELATED_IMAGE_SELINUXD"
)

// daemonTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type daemonTunables struct {
	selinuxdImage    string
	logEnricherImage string
	watchNamespace   string
}

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *ReconcileSPOd) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = event.NewAPIRecorder(mgr.GetEventRecorderFor(r.Name()))

	dt, err := getTunables()
	if err != nil {
		return errors.Wrap(err, "get tunables")
	}

	r.baseSPOd = getEffectiveSPOd(dt)

	if err := r.createConfigIfNotExist(ctx); err != nil {
		return errors.Wrap(err, "create config if not existing")
	}

	r.scheme = mgr.GetScheme()
	r.watchNamespace = dt.watchNamespace
	r.namespace = config.GetOperatorNamespace()

	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&spodv1alpha1.SecurityProfilesOperatorDaemon{}).
		Owns(&appsv1.DaemonSet{}).
		WithEventFilter(resource.NewPredicates(isInOperatorNamespace)).
		Complete(r)
}

func (r *ReconcileSPOd) createConfigIfNotExist(ctx context.Context) error {
	obj := bindata.DefaultSPOD.DeepCopy()
	obj.Namespace = config.GetOperatorNamespace()

	if err := r.client.Create(ctx, obj); !k8serrors.IsAlreadyExists(err) {
		return errors.Wrap(err, "create SecurityProfilesOperatorDaemon object")
	}

	return nil
}

func getTunables() (*daemonTunables, error) {
	dt := &daemonTunables{}
	dt.watchNamespace = os.Getenv(config.RestrictNamespaceEnvKey)

	selinuxdImage := os.Getenv(selinuxdImageKey)
	if selinuxdImage == "" {
		return dt, errors.New("invalid selinuxd image")
	}
	dt.selinuxdImage = selinuxdImage
	return dt, nil
}

func getEffectiveSPOd(dt *daemonTunables) *appsv1.DaemonSet {
	refSPOd := bindata.Manifest.DeepCopy()
	refSPOd.SetNamespace(config.GetOperatorNamespace())

	daemon := &refSPOd.Spec.Template.Spec.Containers[0]
	if dt.watchNamespace != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.RestrictNamespaceEnvKey,
			Value: dt.watchNamespace,
		})
	}

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[1]
	selinuxd.Image = dt.selinuxdImage

	logEnricher := &refSPOd.Spec.Template.Spec.Containers[2]
	logEnricher.Image = dt.logEnricherImage

	sepolImage := &refSPOd.Spec.Template.Spec.InitContainers[1]
	sepolImage.Image = dt.selinuxdImage // selinuxd ships the policies as well

	// Disable SELinux configuration when SELinux is not in enforcing mode
	if selinux.EnforceMode() != selinux.Enforcing {
		for i := range refSPOd.Spec.Template.Spec.InitContainers {
			refSPOd.Spec.Template.Spec.InitContainers[i].SecurityContext.SELinuxOptions = nil
		}
		for i := range refSPOd.Spec.Template.Spec.Containers {
			refSPOd.Spec.Template.Spec.Containers[i].SecurityContext.SELinuxOptions = nil
		}
	}
	return refSPOd
}

func isInOperatorNamespace(obj runtime.Object) bool {
	spod, ok := obj.(*spodv1alpha1.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	return spod.GetNamespace() == config.GetOperatorNamespace()
}
