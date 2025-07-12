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
	"encoding/json"
	"errors"
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
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
	ManageWebhookKey CtxKey = "ManageWebhook"
	selinuxdImageKey string = "RELATED_IMAGE_SELINUXD"
)

var (
	ErrJsonEnricherVolSourceNotFound    = errors.New("no json enricher volume source in configmap found")
	ErrJsonEnricherVolMountPathNotFound = errors.New("no json enricher mount path in configmap found")
)

// daemonTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type daemonTunables struct {
	selinuxdImage                  string
	logEnricherImage               string
	jsonEnricherImage              string
	watchNamespace                 string
	seccompLocalhostProfile        string
	containerRuntime               string
	bpfRecorderSeccompProfile      string
	jsonEnricherLogVolumeSource    *corev1.VolumeSource // Optionally provide a volume for usage in JSON Enricher
	jsonEnricherLogVolumeMountPath string
}

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *ReconcileSPOd) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
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

	node := &corev1.Node{}

	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName != "" {
		objectKey := client.ObjectKey{Name: nodeName}

		err := r.clientReader.Get(ctx, objectKey, node)
		if err != nil {
			return dt, fmt.Errorf("getting cluster node object: %w", err)
		}
	}

	dt.seccompLocalhostProfile = util.GetSeccompLocalhostProfilePath(node, bindata.LocalSeccompProfilePath)
	dt.bpfRecorderSeccompProfile = util.GetSeccompLocalhostProfilePath(node, bindata.LocalSeccompBpfRecorderProfilePath)
	dt.containerRuntime = util.GetContainerRuntime(node)

	dt.selinuxdImage, err = r.getSelinuxdImage(ctx, node)
	if err != nil {
		return dt, fmt.Errorf("could not determine selinuxd image: %w", err)
	}

	dt.jsonEnricherLogVolumeSource, dt.jsonEnricherLogVolumeMountPath, err = r.getJsonEnricherVolume(ctx)
	if err != nil &&
		!errors.Is(err, ErrJsonEnricherVolSourceNotFound) && !errors.Is(err, ErrJsonEnricherVolMountPathNotFound) {
		return dt, fmt.Errorf("could not determine json enricher volume: %w", err)
	}

	return dt, nil
}

func (r *ReconcileSPOd) getJsonEnricherVolume(ctx context.Context) (*corev1.VolumeSource, string, error) {
	operatorCm, err := util.GetOperatorConfigMap(ctx, r.clientReader)
	if err != nil {
		return nil, "", err
	}

	var volumeSource corev1.VolumeSource

	logVolumeJson, exists := operatorCm.Data[util.JsonEnricherLogVolumeSourceJson]
	if !exists {
		return nil, "", ErrJsonEnricherVolSourceNotFound
	}

	err = json.Unmarshal([]byte(logVolumeJson), &volumeSource)
	if err != nil {
		return nil, "", err
	}

	logVolumeMountPath, exists := operatorCm.Data[util.JsonEnricherLogVolumeMountPath]
	if !exists {
		return nil, "", ErrJsonEnricherVolMountPathNotFound
	}

	r.log.Info("Parsed JSON Enricher Volume details from ConfigMap",
		"volumeSource", volumeSource,
		"logVolumeMountPath", logVolumeMountPath)

	return &volumeSource, logVolumeMountPath, nil
}

func (r *ReconcileSPOd) getSelinuxdImage(ctx context.Context, node *corev1.Node) (string, error) {
	operatorCm, err := util.GetOperatorConfigMap(ctx, r.clientReader)
	if err != nil {
		return "", err
	}

	selinuxdImageMapping := operatorCm.Data[util.SelinuxdImageMappingKey]

	selinuxdImageEnvVar, err := util.MatchSelinuxdImageJSONMapping(node, []byte(selinuxdImageMapping))
	if err != nil {
		return "", fmt.Errorf("matching selinuxd image: %w", err)
	}

	// not checking selinuxdImageEnvVar is fine here as os.Getenv returns an empty string in that case
	selinuxdImage := os.Getenv(selinuxdImageEnvVar)
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

	daemon := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDDaemon]
	if dt.watchNamespace != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.RestrictNamespaceEnvKey,
			Value: dt.watchNamespace,
		})
	}

	if dt.seccompLocalhostProfile != "" {
		daemon.SecurityContext.SeccompProfile.LocalhostProfile = &dt.seccompLocalhostProfile
	}

	nonRootEnabler := &refSPOd.Spec.Template.Spec.InitContainers[bindata.InitContainerIDNonRootenabler]
	nonRootEnabler.Args = append(nonRootEnabler.Args, "--runtime="+dt.containerRuntime)

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDSelinuxd]
	selinuxd.Image = dt.selinuxdImage

	logEnricher := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDLogEnricher]
	logEnricher.Image = dt.logEnricherImage

	bpfRecorder := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDBpfRecorder]
	if dt.bpfRecorderSeccompProfile != "" {
		bpfRecorder.SecurityContext.SeccompProfile.LocalhostProfile = &dt.bpfRecorderSeccompProfile
	}

	updateJsonEnricherSpec(dt, refSPOd)

	sepolImage := &refSPOd.Spec.Template.Spec.InitContainers[bindata.InitContainerIDSelinuxSharedPoliciesCopier]
	sepolImage.Image = dt.selinuxdImage // selinuxd ships the policies as well

	return refSPOd
}

func updateJsonEnricherSpec(dt *daemonTunables, refSPOd *appsv1.DaemonSet) {
	jsonEnricher := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDJsonEnricher]
	jsonEnricher.Image = dt.jsonEnricherImage

	if dt.jsonEnricherLogVolumeSource != nil {
		volume, mount := bindata.CustomLogVolume(dt.jsonEnricherLogVolumeMountPath,
			dt.jsonEnricherLogVolumeSource)
		// Reference the Volume at Pod level
		refSPOd.Spec.Template.Spec.Volumes = append(refSPOd.Spec.Template.Spec.Volumes, volume)
		// Mount it only for the Json Enricher container
		jsonEnricher.VolumeMounts = append(jsonEnricher.VolumeMounts, mount)
	}
}

func isInOperatorNamespace(obj runtime.Object) bool {
	spod, ok := obj.(*spodv1alpha1.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	return spod.GetNamespace() == config.GetOperatorNamespace()
}
