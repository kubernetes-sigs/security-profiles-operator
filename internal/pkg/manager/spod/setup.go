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

package spod

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
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
)

var (
	ErrJsonEnricherVolSourceNotFound = errors.New(
		"no json enricher volume source in configmap found",
	)
	ErrJsonEnricherVolMountPathNotFound = errors.New(
		"no json enricher mount path in configmap found",
	)
	// errInvalidTunable is returned for an operator environment variable
	// which the daemon would refuse.
	errInvalidTunable = errors.New("invalid daemon tunable")
)

// daemonTunables defines the parameters to tune/modify for the
// Security-Profiles-Operator-Daemon.
type daemonTunables struct {
	selinuxdImage  string
	watchNamespace string
	// maxMetricSeries is passed on to the daemon unless empty.
	maxMetricSeries string
}

// Setup adds a controller that reconciles the SPOD and its operands.
func (r *ReconcileSPOd) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	_ *metrics.Metrics,
) error {
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = util.NewEventRecorder(mgr, r.Name())
	r.clientReader = mgr.GetAPIReader()
	r.scheme = mgr.GetScheme()

	namespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("get operator namespace: %w", err)
	}

	r.namespace = namespace
	r.env = envFlagsFromEnvironment()

	// The certificate provider does not change while the operator runs,
	// and reading it once through the API reader saves an informer for the
	// cluster operators.
	r.caInjectType, err = bindata.GetCAInjectType(ctx, r.log, r.clientReader)
	if err != nil {
		return fmt.Errorf("get ca inject type: %w", err)
	}

	dt, err := r.getTunables(ctx)
	if err != nil {
		return fmt.Errorf("get tunables: %w", err)
	}

	r.baseSPOd = getEffectiveSPOd(dt)

	// The default SPOD gets created by the elected leader only, so that the
	// replicas do not race for it before the manager runs.
	if err := mgr.Add(&defaultSPODCreator{
		client:        r.client,
		namespace:     r.namespace,
		staticWebhook: isStaticWebhook(ctx),
	}); err != nil {
		return fmt.Errorf("add default SPOD creator: %w", err)
	}

	inNamespace := func(obj client.Object) bool { return isInNamespace(obj, r.namespace) }
	inOperatorNamespace := builder.WithPredicates(predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return inNamespace(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return inNamespace(e.Object) },
		UpdateFunc:  func(e event.UpdateEvent) bool { return inNamespace(e.ObjectNew) },
		GenericFunc: func(e event.GenericEvent) bool { return inNamespace(e.Object) },
	})

	if err := r.setupAllowList(mgr, inOperatorNamespace); err != nil {
		return fmt.Errorf("setting up the allowed syscalls controller: %w", err)
	}

	b := ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()).
		For(&spodapi.SecurityProfilesOperatorDaemon{}, inOperatorNamespace).
		Owns(&appsv1.DaemonSet{}, inOperatorNamespace).
		// The metrics service gets restored if it is deleted.
		Owns(&corev1.Service{}, inOperatorNamespace).
		// The objects of the managed webhook get restored if they are changed
		// or deleted. The SPOD does not own them, so that deleting the SPOD
		// does not remove the webhook, which the webhook configurations left
		// behind still call.
		Watches(
			&appsv1.Deployment{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(r.isNamedInNamespace(bindata.WebhookName)),
		).
		Watches(
			&policyv1.PodDisruptionBudget{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(r.isNamedInNamespace(bindata.WebhookName)),
		).
		Watches(
			&corev1.Service{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(r.isNamedInNamespace(bindata.WebhookServiceName)),
		).
		// The operator ConfigMap configures the log volume of the JSON
		// enricher. The manager caches it by name.
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(predicate.NewPredicateFuncs(func(obj client.Object) bool {
				return inNamespace(obj) && obj.GetName() == util.OperatorConfigMap
			})),
		).
		// The webhook configurations are cluster scoped, so the SPOD cannot
		// own them. They get restored if they are changed or deleted. The
		// manager caches them by name.
		Watches(
			&admissionregv1.MutatingWebhookConfiguration{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(isNamed(bindata.MutatingWebhookConfigName)),
		).
		Watches(
			&admissionregv1.ValidatingWebhookConfiguration{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(isNamed(bindata.ValidatingWebhookConfigName)),
		).
		// The default profiles get restored if they are deleted. Their status
		// changes often and does not matter here.
		Watches(
			&seccompprofileapi.SeccompProfile{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.WithPredicates(deletedWithName(config.LogEnricherProfile)),
		).
		// Nodes can configure a custom kubelet directory through a label,
		// which the SPOd has to mount for the non-root enabler.
		Watches(
			&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			builder.OnlyMetadata,
			builder.WithPredicates(kubeletDirLabelChanged()),
		)

	// Restore the admission policies if they get changed or deleted. Clusters
	// which do not serve their API skip them.
	servesPolicies, err := ServesAdmissionPolicies(mgr.GetRESTMapper())
	if err != nil {
		return err
	}

	r.skipAdmissionPolicies = !servesPolicies

	r.spodPolicies, err = bindata.GetSpodAdmissionPolicies(r.namespace)
	if err != nil {
		return fmt.Errorf("get spod admission policies: %w", err)
	}

	if servesPolicies {
		isAdmissionPolicy := builder.WithPredicates(predicate.NewPredicateFuncs(
			func(obj client.Object) bool { return bindata.IsAdmissionPolicyName(obj.GetName()) },
		))

		for _, obj := range []client.Object{
			&admissionregv1.ValidatingAdmissionPolicy{},
			&admissionregv1.ValidatingAdmissionPolicyBinding{},
		} {
			b = b.Watches(
				obj,
				handler.EnqueueRequestsFromMapFunc(r.allSPODs),
				isAdmissionPolicy,
			)
		}
	}

	b, err = r.watchServiceMonitorAPI(mgr, b)
	if err != nil {
		return err
	}

	b, err = r.watchCertManager(mgr, b)
	if err != nil {
		return err
	}

	return b.Complete(r)
}

// watchCertManager restores the cert-manager resources if they get deleted.
// Clusters which do not serve the cert-manager API cannot get them created
// either.
func (r *ReconcileSPOd) watchCertManager(
	mgr ctrl.Manager, b *builder.Builder,
) (*builder.Builder, error) {
	if r.caInjectType != bindata.CAInjectTypeCertManager {
		return b, nil
	}

	servesCertManager, err := ServesCertManager(mgr.GetRESTMapper())
	if err != nil {
		return nil, err
	}

	r.watchesCertManager = servesCertManager

	if !servesCertManager {
		return b, nil
	}

	isCertManagerResource := builder.WithPredicates(predicate.NewPredicateFuncs(
		func(obj client.Object) bool {
			return isInNamespace(obj, r.namespace) &&
				bindata.IsCertManagerResourceName(obj.GetName())
		},
	))

	for _, obj := range []client.Object{&certmanagerv1.Issuer{}, &certmanagerv1.Certificate{}} {
		b = b.Watches(
			obj,
			handler.EnqueueRequestsFromMapFunc(r.allSPODs),
			isCertManagerResource,
		)
	}

	return b, nil
}

// watchServiceMonitorAPI reconciles the SPODs once the ServiceMonitor API
// gets installed, if the cluster does not serve it yet, so that they create
// their ServiceMonitor.
func (r *ReconcileSPOd) watchServiceMonitorAPI(
	mgr ctrl.Manager, b *builder.Builder,
) (*builder.Builder, error) {
	served, err := ServesServiceMonitors(mgr.GetRESTMapper())
	if err != nil {
		r.log.Error(err, "Cannot check whether the ServiceMonitor API is served")
	}

	if served {
		return b, nil
	}

	events := make(chan event.GenericEvent)

	if err := mgr.Add(&serviceMonitorWatcher{
		mapper:   mgr.GetRESTMapper(),
		interval: serviceMonitorRetry,
		events:   events,
		served:   func() { r.serviceMonitorMissing.Store(0) },
		log:      r.log,
	}); err != nil {
		return nil, fmt.Errorf("add ServiceMonitor API watcher: %w", err)
	}

	return b.WatchesRawSource(
		source.Channel(events, handler.EnqueueRequestsFromMapFunc(r.allSPODs)),
	), nil
}

// isNamed returns a predicate which passes the objects of the name.
func isNamed(name string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == name
	})
}

// deletedWithName returns a predicate which passes the deletion of objects of
// the name only.
func deletedWithName(name string) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(event.CreateEvent) bool { return false },
		UpdateFunc:  func(event.UpdateEvent) bool { return false },
		DeleteFunc:  func(e event.DeleteEvent) bool { return e.Object.GetName() == name },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// isNamedInNamespace returns a predicate which passes the objects of the name
// in the operator namespace.
func (r *ReconcileSPOd) isNamedInNamespace(name string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetName() == name && isInNamespace(obj, r.namespace)
	})
}

// ServesCertManager returns true if the cluster serves the Issuer and
// Certificate API of cert-manager. It returns an error if the mapper cannot
// tell, like ServesAdmissionPolicies.
func ServesCertManager(mapper meta.RESTMapper) (bool, error) {
	return servesKinds(mapper, certmanagerv1.SchemeGroupVersion.WithKind("Issuer"),
		certmanagerv1.SchemeGroupVersion.WithKind("Certificate"))
}

// ServesAdmissionPolicies returns true if the cluster serves the
// ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding API, which
// Kubernetes 1.30 and later do. It returns an error if the mapper cannot tell,
// for example because the discovery failed, so that the caller does not treat
// a temporary failure as a missing API.
func ServesAdmissionPolicies(mapper meta.RESTMapper) (bool, error) {
	return servesKinds(mapper,
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicy"),
		admissionregv1.SchemeGroupVersion.WithKind("ValidatingAdmissionPolicyBinding"))
}

// servesKinds returns true if the mapper knows all the kinds.
func servesKinds(mapper meta.RESTMapper, gvks ...schema.GroupVersionKind) (bool, error) {
	for _, gvk := range gvks {
		if _, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version); err != nil {
			if meta.IsNoMatchError(err) {
				return false, nil
			}

			return false, fmt.Errorf("get REST mapping of %s: %w", gvk.Kind, err)
		}
	}

	return true, nil
}

// defaultSPODCreator creates the default SPOD if it does not exist. It runs
// as a leader elected runnable of the manager, so that only one replica
// writes to the API server, and only once the manager runs.
type defaultSPODCreator struct {
	client        client.Client
	namespace     string
	staticWebhook bool
	// backoff overrides defaultSPODCreateBackoff if it has steps.
	backoff wait.Backoff
}

// defaultSPODCreateBackoff retries the creation of the default SPOD for about
// a minute. An error returned by a runnable stops the manager, so a transient
// API error right after the leader election would restart the operator.
var defaultSPODCreateBackoff = wait.Backoff{
	Duration: time.Second,
	Factor:   2,
	Jitter:   0.1,
	Steps:    7,
}

var _ manager.LeaderElectionRunnable = &defaultSPODCreator{}

// NeedLeaderElection returns true, because the default SPOD is created by
// the leader only.
func (c *defaultSPODCreator) NeedLeaderElection() bool {
	return true
}

// Start creates the default SPOD and returns. Transient errors are retried.
func (c *defaultSPODCreator) Start(ctx context.Context) error {
	obj := bindata.DefaultSPOD.DeepCopy()
	obj.Namespace = c.namespace
	obj.Spec.Webhook.StaticConfig = &c.staticWebhook

	backoff := c.backoff
	if backoff.Steps == 0 {
		backoff = defaultSPODCreateBackoff
	}

	var lastErr error

	err := wait.ExponentialBackoffWithContext(
		ctx,
		backoff,
		func(ctx context.Context) (bool, error) {
			lastErr = c.client.Create(ctx, obj.DeepCopy())

			switch {
			case lastErr == nil, k8serrors.IsAlreadyExists(lastErr):
				return true, nil
			case k8serrors.IsInvalid(lastErr), k8serrors.IsBadRequest(lastErr):
				// A retry cannot fix these. A Forbidden one is retried,
				// right after an install the RBAC bindings may not have
				// reached the authorizer yet.
				return false, lastErr
			default:
				return false, nil
			}
		},
	)
	if err != nil {
		if lastErr != nil {
			err = lastErr
		}

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
	// The daemons watch the same namespaces as the manager, which includes
	// the WATCH_NAMESPACE set by OLM.
	dt.watchNamespace = config.WatchNamespaces()

	dt.maxMetricSeries, err = maxMetricSeries()
	if err != nil {
		return dt, err
	}

	node := &corev1.Node{}

	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName != "" {
		objectKey := client.ObjectKey{Name: nodeName}

		err := r.clientReader.Get(ctx, objectKey, node)
		if err != nil {
			return dt, fmt.Errorf("getting cluster node object: %w", err)
		}
	}

	dt.selinuxdImage, err = r.getSelinuxdImage(ctx, node)
	if err != nil {
		return dt, fmt.Errorf("could not determine selinuxd image: %w", err)
	}

	return dt, nil
}

// maxMetricSeries returns the limit of the metric series of the daemon from
// the operator environment, or an empty string if it is unset. A value the
// daemon would refuse is rejected here, where it gets reported, instead of
// making every daemon pod fail to start.
func maxMetricSeries() (string, error) {
	value := os.Getenv(config.MaxMetricSeriesEnvKey)
	if value == "" {
		return "", nil
	}

	series, err := strconv.Atoi(value)
	if err != nil || series < 0 {
		return "", fmt.Errorf(
			"%w: %s must be a non-negative integer: %q",
			errInvalidTunable, config.MaxMetricSeriesEnvKey, value,
		)
	}

	return strconv.Itoa(series), nil
}

// isJsonEnricherVolumeNotConfigured returns true if the error of
// getJsonEnricherVolume tells that the operator ConfigMap does not configure
// a log volume for the JSON enricher, which is not an error.
func isJsonEnricherVolumeNotConfigured(err error) bool {
	return errors.Is(err, ErrJsonEnricherVolSourceNotFound) ||
		errors.Is(err, ErrJsonEnricherVolMountPathNotFound)
}

// getJsonEnricherVolume reads the log volume of the JSON enricher from the
// cached operator ConfigMap. The sentinel errors tell that the ConfigMap does
// not configure one, every other error that it could not be read.
func (r *ReconcileSPOd) getJsonEnricherVolume(
	ctx context.Context,
) (*corev1.VolumeSource, string, error) {
	operatorCm := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: r.namespace, Name: util.OperatorConfigMap}

	if err := r.client.Get(ctx, key, operatorCm); err != nil {
		return nil, "", fmt.Errorf("getting ConfigMap %s: %w", key, err)
	}

	var volumeSource corev1.VolumeSource

	logVolumeJson, exists := operatorCm.Data[util.JsonEnricherLogVolumeSourceJson]
	if !exists {
		return nil, "", ErrJsonEnricherVolSourceNotFound
	}

	if err := json.Unmarshal([]byte(logVolumeJson), &volumeSource); err != nil {
		return nil, "", fmt.Errorf("parsing the JSON enricher log volume source: %w", err)
	}

	logVolumeMountPath, exists := operatorCm.Data[util.JsonEnricherLogVolumeMountPath]
	if !exists {
		return nil, "", ErrJsonEnricherVolMountPathNotFound
	}

	r.log.V(config.VerboseLevel).Info("Parsed JSON Enricher Volume details from ConfigMap",
		"volumeSource", volumeSource,
		"logVolumeMountPath", logVolumeMountPath)

	return &volumeSource, logVolumeMountPath, nil
}

func (r *ReconcileSPOd) getSelinuxdImage(ctx context.Context, node *corev1.Node) (string, error) {
	selinuxdImage, err := util.GetSelinuxdImage(ctx, r.clientReader, r.namespace, node)
	if err != nil {
		return "", err
	}

	r.log.Info("using selinuxd image", "image", selinuxdImage)

	return selinuxdImage, nil
}

// getEffectiveSPOd returns the base SPOd with the tunables applied. The
// images of the enrichers and the recorder are set per reconciliation, see
// configureRecording, and the name and namespace by getConfiguredSPOd.
func getEffectiveSPOd(dt *daemonTunables) *appsv1.DaemonSet {
	refSPOd := bindata.Manifest.DeepCopy()

	daemon := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDDaemon]
	if dt.watchNamespace != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.RestrictNamespaceEnvKey,
			Value: dt.watchNamespace,
		})
	}

	if dt.maxMetricSeries != "" {
		daemon.Env = append(daemon.Env, corev1.EnvVar{
			Name:  config.MaxMetricSeriesEnvKey,
			Value: dt.maxMetricSeries,
		})
	}

	selinuxd := &refSPOd.Spec.Template.Spec.Containers[bindata.ContainerIDSelinuxd]
	selinuxd.Image = dt.selinuxdImage

	sepolImage := &refSPOd.Spec.Template.Spec.InitContainers[bindata.InitContainerIDSelinuxSharedPoliciesCopier]
	sepolImage.Image = dt.selinuxdImage // selinuxd ships the policies as well

	return refSPOd
}

// isInNamespace returns true if the object is in the namespace. The
// predicates of several watched kinds use it, so it must accept any kind, not
// just the SPOD.
func isInNamespace(obj client.Object, namespace string) bool {
	if obj == nil {
		return false
	}

	return obj.GetNamespace() == namespace
}
