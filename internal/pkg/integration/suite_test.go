//go:build integration

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

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spoconfig "sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
)

const (
	// assetsEnvKey points to the directory of the envtest binaries.
	assetsEnvKey = "KUBEBUILDER_ASSETS"
	// logEnvKey enables the controller logs if set to a verbosity level.
	logEnvKey = "SPO_INTEGRATION_LOG"
	// requiredEnvKey fails the tests instead of skipping them when
	// assetsEnvKey is empty, so that a failed download of the envtest
	// binaries does not pass make test-integration.
	requiredEnvKey = "SPO_INTEGRATION_REQUIRED"

	// operatorNamespace is the namespace of the SPOd DaemonSet, which the
	// node status controller takes from the environment.
	operatorNamespace = "spo-integration-operator"

	eventuallyTimeout = 30 * time.Second
	tick              = 100 * time.Millisecond
	// quietPeriod is how long a test waits for a reconcile which must not
	// happen.
	quietPeriod = 2 * time.Second
)

var (
	// cfg is the configuration of the envtest API server, nil if the tests
	// are skipped.
	cfg *rest.Config
	// k8sClient is the uncached client the tests use to set up and inspect
	// the objects.
	k8sClient client.Client
	// skipReason tells why the tests are skipped, empty if they run.
	skipReason string
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	if os.Getenv(assetsEnvKey) == "" {
		if required, err := strconv.ParseBool(os.Getenv(requiredEnvKey)); err == nil && required {
			fmt.Fprintf(os.Stderr, "%s is not set, but %s is\n", assetsEnvKey, requiredEnvKey)

			return 1
		}

		skipReason = assetsEnvKey + " is not set, run `make test-integration` " +
			"or point it to the envtest binaries of `setup-envtest use -p path`"

		return m.Run()
	}

	ctrl.SetLogger(newLogger())

	// The node status controller looks up the SPOd DaemonSet in the operator
	// namespace, which it takes from the environment.
	if err := os.Setenv(spoconfig.OperatorNamespaceEnvKey, operatorNamespace); err != nil {
		fmt.Fprintf(os.Stderr, "setting operator namespace: %v\n", err)

		return 1
	}

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "..", "deploy", "base-crds", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}

	var err error

	cfg, err = env.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting envtest: %v\n", err)

		return 1
	}

	defer func() {
		if err := env.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "stopping envtest: %v\n", err)
		}
	}()

	k8sClient, err = client.New(cfg, client.Options{Scheme: newScheme()})
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating client: %v\n", err)

		return 1
	}

	// Without the namespace controller, a deleted namespace stays
	// terminating, so the operator namespace is shared by every run.
	if err := k8sClient.Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: operatorNamespace},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "creating operator namespace: %v\n", err)

		return 1
	}

	return m.Run()
}

// newLogger returns the logger of the controllers, which discards the logs
// unless logEnvKey is set to a verbosity level.
func newLogger() logr.Logger {
	verbosity := os.Getenv(logEnvKey)
	if verbosity == "" {
		return logr.Discard()
	}

	level := 0
	if _, err := fmt.Sscanf(verbosity, "%d", &level); err != nil {
		level = 0
	}

	return funcr.New(func(prefix, args string) {
		fmt.Fprintln(os.Stderr, prefix, args)
	}, funcr.Options{Verbosity: level})
}

// newScheme returns a scheme with the core and operator APIs. Every manager
// gets its own scheme, because the controllers add their APIs to the scheme
// of the manager while the other tests run.
func newScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()

	for _, add := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		seccompprofileapi.AddToScheme,
		selinuxprofileapi.AddToScheme,
		apparmorprofileapi.AddToScheme,
		profilebindingapi.AddToScheme,
		profilerecordingapi.AddToScheme,
		secprofnodestatusapi.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			panic(fmt.Sprintf("building scheme: %v", err))
		}
	}

	return scheme
}

// requireEnv skips the test if the envtest environment is not available.
func requireEnv(t *testing.T) {
	t.Helper()

	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// newNamespace creates a namespace for the test and returns its name. The
// namespace is not deleted, because without the namespace controller it would
// stay terminating anyway, and envtest discards everything at the end.
func newNamespace(t *testing.T) string {
	t.Helper()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "spo-it-"}}
	require.NoError(t, k8sClient.Create(t.Context(), ns))

	return ns.Name
}

// podGets counts the reads of pods through the client of a manager. The pod
// reconcilers read the pod of the request first, so the reads of a pod count
// its reconciles.
type podGets struct {
	mu    sync.Mutex
	count map[types.NamespacedName]int
}

func (p *podGets) inc(key types.NamespacedName) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.count[key]++
}

// get returns the number of reads of the pod.
func (p *podGets) get(key types.NamespacedName) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.count[key]
}

// managerOptions configures startManager.
type managerOptions struct {
	// namespaces restricts the cache of the namespaced objects to these
	// namespaces, so that the controller does not act on the objects of
	// other tests.
	namespaces []string
}

// startManager starts a manager with the controller and returns the counter
// of the pod reads of its client. The manager stops at the end of the test.
func startManager(t *testing.T, ctrlr controller.Controller, opts managerOptions) *podGets {
	t.Helper()

	gets := &podGets{count: map[types.NamespacedName]int{}}

	defaultNamespaces := map[string]cache.Config{}
	for _, ns := range opts.namespaces {
		defaultNamespaces[ns] = cache.Config{}
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  newScheme(),
		Metrics: metricsserver.Options{BindAddress: "0"},
		Cache:   cache.Options{DefaultNamespaces: defaultNamespaces},
		// Every test registers the controllers with the same names.
		Controller: config.Controller{SkipNameValidation: new(true)},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			c, err := client.NewWithWatch(config, options)
			if err != nil {
				return nil, err
			}

			return interceptor.NewClient(c, interceptor.Funcs{
				Get: func(
					ctx context.Context, c client.WithWatch, key client.ObjectKey,
					obj client.Object, opts ...client.GetOption,
				) error {
					if _, ok := obj.(*corev1.Pod); ok {
						gets.inc(key)
					}

					return c.Get(ctx, key, obj, opts...)
				},
			}), nil
		},
	})
	require.NoError(t, err)

	if sb := ctrlr.SchemeBuilder(); sb != nil {
		require.NoError(t, sb.AddToScheme(mgr.GetScheme()))
	}

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, ctrlr.Setup(ctx, mgr, nil))

	done := make(chan error, 1)

	go func() {
		done <- mgr.Start(ctx)
	}()

	t.Cleanup(func() {
		cancel()

		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager stopped with error: %v", err)
		}
	})

	syncCtx, syncCancel := context.WithTimeout(ctx, eventuallyTimeout)
	defer syncCancel()

	require.True(t, mgr.GetCache().WaitForCacheSync(syncCtx), "waiting for the cache sync")

	return gets
}

// uniqueName returns a name for a cluster scoped object of the test, which
// starts with the provided prefix and ends with the suffix of the namespace
// of the test.
func uniqueName(prefix, namespace string) string {
	return prefix + "-" + strings.TrimPrefix(namespace, "spo-it-")
}

// newPod returns a pod with a single container, which the test can modify
// before creating it. The pods are never scheduled, so the API server deletes
// them right away.
func newPod(namespace, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "ctr", Image: "registry.k8s.io/pause:3.10"}},
		},
	}
}

// deletePod deletes the pod immediately.
func deletePod(t *testing.T, pod *corev1.Pod) {
	t.Helper()

	require.NoError(t, k8sClient.Delete(t.Context(), pod, client.GracePeriodSeconds(0)))
	require.Eventually(t, func() bool {
		err := k8sClient.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{})

		return apierrors.IsNotFound(err)
	}, eventuallyTimeout, tick, "waiting for the pod deletion")
}

// eventuallyGet waits until the object read from the API server satisfies
// the condition.
func eventuallyGet[T client.Object](
	t *testing.T, key client.ObjectKey, obj T, condition func(T) bool, msg string,
) {
	t.Helper()

	require.Eventually(t, func() bool {
		if err := k8sClient.Get(t.Context(), key, obj); err != nil {
			return false
		}

		return condition(obj)
	}, eventuallyTimeout, tick, msg)
}
