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
	"errors"
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// CtxKey type for spod context keys.
type CtxKey string

const (
	// ManageWebhookKey value key used in the Setup.Context for ManageWebhook value.
	ManageWebhookKey  CtxKey = "ManageWebhook"
	selinuxdImageKey  string = "RELATED_IMAGE_SELINUXD"
	rbacProxyImageKey string = "RELATED_IMAGE_RBAC_PROXY"
)

// daemonTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type daemonTunables struct {
	selinuxdImage           string
	rbacProxyImage          string
	logEnricherImage        string
	watchNamespace          string
	seccompLocalhostProfile string
	containerRuntime        string
}

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *ReconcileSPOd) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = mgr.GetEventRecorderFor(r.Name())
	r.clientReader = mgr.GetAPIReader()

	dt, err := r.getTunables(ctx)
	if err != nil {
		return fmt.Errorf("get tunables: %w", err)
	}

	r.baseSPOd = getEffectiveSPOd(dt)

	if err := r.createConfigIfNotExist(ctx); err != nil {
		return fmt.Errorf("create config if not existing: %w", err)
	}

	r.scheme = mgr.GetScheme()
	r.watchNamespace = dt.watchNamespace
	r.namespace = config.GetOperatorNamespace()

	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&spodv1alpha1.SecurityProfilesOperatorDaemon{}).
		Owns(&appsv1.DaemonSet{}).
		WithEventFilter(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return isInOperatorNamespace(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return isInOperatorNamespace(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return isInOperatorNamespace(e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return isInOperatorNamespace(e.Object) },
		}).
		Complete(r)
}

func (r *ReconcileSPOd) createConfigIfNotExist(ctx context.Context) error {
	obj := bindata.DefaultSPOD.DeepCopy()
	obj.Namespace = config.GetOperatorNamespace()
	obj.Spec.StaticWebhookConfig = isStaticWebhook(ctx)

	if err := r.client.Create(ctx, obj); err != nil && !k8serrors.IsAlreadyExists(err) {
		return fmt.Errorf("create SecurityProfilesOperatorDaemon object: %w", err)
	}

	return nil
}

func isStaticWebhook(ctx context.Context) bool {
	v, ok := ctx.Value(ManageWebhookKey).(bool)
	if ok {
		return !v
	}
	// the webhook is by default managed by the operator
	return false
}

func (r *ReconcileSPOd) getTunables(ctx context.Context) (*daemonTunables, error) {
	var err error

	dt := &daemonTunables{}
	dt.watchNamespace = os.Getenv(config.RestrictNamespaceEnvKey)

	rbacProxyImage := os.Getenv(rbacProxyImageKey)
	if rbacProxyImage == "" {
		return dt, errors.New("invalid rbac proxy image")
	}
	dt.rbacProxyImage = rbacProxyImage

	node := &corev1.Node{}
	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName != "" {
		objectKey := client.ObjectKey{Name: nodeName}
		err := r.clientReader.Get(ctx, objectKey, node)
		if err != nil {
			return dt, fmt.Errorf("getting cluster node object: %w", err)
		}
	}
	dt.seccompLocalhostProfile = util.GetSeccompLocalhostProfilePath(node)
	dt.containerRuntime = util.GetContainerRuntime(node)
	dt.selinuxdImage, err = r.getSelinuxdImage(ctx, node)
	if err != nil {
		return dt, fmt.Errorf("could not determine selinuxd image: %w", err)
	}

	return dt, nil
}

func (r *ReconcileSPOd) getSelinuxdImage(ctx context.Context, node *corev1.Node) (string, error) {
	var operatorCm corev1.ConfigMap
	operatorCmName := types.NamespacedName{
		Namespace: config.GetOperatorNamespace(),
		Name:      util.OperatorConfigMap,
	}

	if err := r.clientReader.Get(ctx, operatorCmName, &operatorCm); err != nil {
		return "", err
	}
	selinuxdImageMapping := operatorCm.Data[util.SelinuxdImageMappingKey]

	selinuxdImage, err := util.MatchSelinuxdImageJSONMapping(node, []byte(selinuxdImageMapping))
	if err != nil {
		return "", fmt.Errorf("matching selinuxd image: %w", err)
	}

	if selinuxdImage != "" {
		r.log.Info("matched selinuxd image against nodeInfo", "image", selinuxdImage)
		return selinuxdImage, nil
	}

	selinuxdImage = os.Getenv(selinuxdImageKey)
	if selinuxdImage != "" {
		r.log.Info("using selinuxd image from envVar", "image", selinuxdImage)
		return selinuxdImage, nil
	}

	return "", errors.New("invalid selinuxd image")
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
	if dt.seccompLocalhostProfile != "" {
		daemon.SecurityContext.SeccompProfile.LocalhostProfile = &dt.seccompLocalhostProfile
	}

	nonRootEnabler := &refSPOd.Spec.Template.Spec.InitContainers[0]
	nonRootEnabler.Args = append(nonRootEnabler.Args, "--runtime="+dt.containerRuntime)

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[1]
	selinuxd.Image = dt.selinuxdImage

	logEnricher := &refSPOd.Spec.Template.Spec.Containers[2]
	logEnricher.Image = dt.logEnricherImage

	metrixCtr := &refSPOd.Spec.Template.Spec.Containers[4]
	metrixCtr.Image = dt.rbacProxyImage

	sepolImage := &refSPOd.Spec.Template.Spec.InitContainers[1]
	sepolImage.Image = dt.selinuxdImage // selinuxd ships the policies as well

	return refSPOd
}

func isInOperatorNamespace(obj runtime.Object) bool {
	spod, ok := obj.(*spodv1alpha1.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	return spod.GetNamespace() == config.GetOperatorNamespace()
}
