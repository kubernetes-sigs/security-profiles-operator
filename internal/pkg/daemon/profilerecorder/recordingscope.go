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

package profilerecorder

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	// recordingScopeTTL is how long the selectors of the recording webhook
	// and the labels of a namespace are used before they get read again.
	// Every update of an annotated pod which is not recorded checks them,
	// like the ones of the pods whose annotations got rejected. They are
	// read again for the first rejection of a pod, see authorizedProfiles.
	recordingScopeTTL = 30 * time.Second
	// maxScopeNamespaces bounds the namespaces whose labels are cached.
	maxScopeNamespaces uint64 = 1024
)

// recordingSelectors are the selectors of the recording webhook.
type recordingSelectors struct {
	namespace k8slabels.Selector
	object    k8slabels.Selector
}

// namespaceLabels are the labels of a namespace, which does not exist if gone
// is set.
type namespaceLabels struct {
	labels k8slabels.Set
	gone   bool
}

// recordingScope caches what tells whether the recording webhook applies to a
// pod, so that the updates of the annotated pods do not read it from the API
// server every time. The zero value is ready to use.
type recordingScope struct {
	mu         sync.Mutex
	selectors  *ttlcache.Cache[struct{}, *recordingSelectors]
	namespaces *ttlcache.Cache[string, namespaceLabels]
	// ttl replaces recordingScopeTTL in tests.
	ttl time.Duration
}

func (s *recordingScope) caches() (
	selectors *ttlcache.Cache[struct{}, *recordingSelectors],
	namespaces *ttlcache.Cache[string, namespaceLabels],
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.selectors == nil {
		ttl := cmp.Or(s.ttl, recordingScopeTTL)
		s.selectors = ttlcache.New(
			ttlcache.WithTTL[struct{}, *recordingSelectors](ttl),
			ttlcache.WithDisableTouchOnHit[struct{}, *recordingSelectors](),
		)
		s.namespaces = ttlcache.New(
			ttlcache.WithTTL[string, namespaceLabels](ttl),
			ttlcache.WithCapacity[string, namespaceLabels](maxScopeNamespaces),
			ttlcache.WithDisableTouchOnHit[string, namespaceLabels](),
		)
	}

	return s.selectors, s.namespaces
}

// forget drops the cached selectors and the cached labels of the namespace,
// so that they get read again.
func (s *recordingScope) forget(namespace string) {
	selectors, namespaces := s.caches()
	selectors.Delete(struct{}{})
	namespaces.Delete(namespace)
}

// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,resourceNames=spo-mutating-webhook-configuration,verbs=get

// recordingEnabled reports whether the recording webhook applies to the pod:
// its namespace selector has to select the namespace of the pod, by default
// the namespaces labeled with bindata.EnableRecordingLabel, and its object
// selector the pod. The namespaces are not watched, the one of a pod which
// starts being recorded is read. The selectors and the labels of the
// namespaces are cached for recordingScopeTTL.
func (r *RecorderReconciler) recordingEnabled(ctx context.Context, pod *corev1.Pod) (bool, error) {
	selectors, err := r.recordingSelectors(ctx)
	if err != nil {
		return false, err
	}

	if !selectors.object.Matches(k8slabels.Set(pod.GetLabels())) {
		return false, nil
	}

	// Like for the webhook, no selector selects every namespace.
	if selectors.namespace.Empty() {
		return true, nil
	}

	namespace, err := r.namespaceLabels(ctx, pod.Namespace)
	if err != nil {
		return false, err
	}

	return !namespace.gone && selectors.namespace.Matches(namespace.labels), nil
}

// recordingSelectors returns the cached selectors of the recording webhook.
func (r *RecorderReconciler) recordingSelectors(ctx context.Context) (*recordingSelectors, error) {
	cache, _ := r.scope.caches()

	if item := cache.Get(struct{}{}); item != nil {
		return item.Value(), nil
	}

	selectors, err := r.recordingWebhookSelectors(ctx)
	if err != nil {
		return nil, err
	}

	cache.Set(struct{}{}, selectors, ttlcache.DefaultTTL)

	return selectors, nil
}

// recordingWebhookSelectors returns the selectors of the recording webhook
// which is deployed. If its configuration does not exist or the daemon may not
// read it, they are the ones which the operator deploys for the SPOD. Other
// errors are returned, so that a transient failure is retried instead of
// caching selectors which may not be the deployed ones.
func (r *RecorderReconciler) recordingWebhookSelectors(
	ctx context.Context,
) (*recordingSelectors, error) {
	webhookConfig, err := r.GetMutatingWebhookConfiguration(
		ctx, r.uncachedClient, bindata.MutatingWebhookConfigName,
	)
	if err == nil && webhookConfig != nil {
		i := slices.IndexFunc(webhookConfig.Webhooks, func(w admissionregv1.MutatingWebhook) bool {
			return w.Name == bindata.RecordingWebhookName
		})
		if i < 0 {
			// The pod authors set the recording annotations of all pods.
			r.log.Info(
				"No recording webhook configured, ignoring all recording annotations",
				"webhookConfiguration", bindata.MutatingWebhookConfigName,
			)

			return &recordingSelectors{
				namespace: k8slabels.Nothing(),
				object:    k8slabels.Nothing(),
			}, nil
		}

		hook := &webhookConfig.Webhooks[i]

		return &recordingSelectors{
			namespace: r.webhookSelector(hook.NamespaceSelector, "namespace"),
			object:    r.webhookSelector(hook.ObjectSelector, "object"),
		}, nil
	}

	if err != nil && !kerrors.IsNotFound(err) && !kerrors.IsForbidden(err) {
		return nil, fmt.Errorf("getting the recording webhook configuration: %w", err)
	}

	logger := r.log
	if err == nil || kerrors.IsNotFound(err) {
		logger = logger.V(config.VerboseLevel)
	}

	logger.Info(
		"Cannot read the recording webhook, using the one configured by the SPOD",
		"webhookConfiguration", bindata.MutatingWebhookConfigName, "error", fmt.Sprint(err),
	)

	spod, err := r.getSPOD(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting SPOD config: %w", err)
	}

	namespaceSelector, objectSelector := bindata.RecordingWebhookSelectors(
		spod.Spec.Webhook.Options, ptr.Deref(spod.Spec.Webhook.StaticConfig, false),
	)

	return &recordingSelectors{
		namespace: r.webhookSelector(namespaceSelector, "namespace"),
		object:    r.webhookSelector(objectSelector, "object"),
	}, nil
}

// webhookSelector converts a selector of a webhook, which selects everything
// if it is nil.
func (r *RecorderReconciler) webhookSelector(
	selector *metav1.LabelSelector, kind string,
) k8slabels.Selector {
	if selector == nil {
		return k8slabels.Everything()
	}

	converted, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		// The API server rejects the webhook with it as well, so the webhook
		// applies to nothing.
		r.log.Error(err, "Invalid selector of the recording webhook", "selector", kind)

		return k8slabels.Nothing()
	}

	return converted
}

// namespaceLabels returns the cached labels of a namespace.
func (r *RecorderReconciler) namespaceLabels(
	ctx context.Context, name string,
) (namespaceLabels, error) {
	_, cache := r.scope.caches()

	if item := cache.Get(name); item != nil {
		return item.Value(), nil
	}

	var labels namespaceLabels

	namespace, err := r.GetNamespace(ctx, r.uncachedClient, name)

	switch {
	case kerrors.IsNotFound(err):
		labels.gone = true
	case err != nil:
		return namespaceLabels{}, fmt.Errorf("get namespace %s: %w", name, err)
	default:
		labels.labels = maps.Clone(namespace.GetLabels())
	}

	cache.Set(name, labels, ttlcache.DefaultTTL)

	return labels, nil
}
