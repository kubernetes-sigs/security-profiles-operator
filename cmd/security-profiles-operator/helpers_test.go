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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
)

const (
	tlsVersion12 = tls.VersionTLS12
	tlsVersion13 = tls.VersionTLS13
)

// newCLIContext returns a context of a command with the given flags parsed
// from args.
func newCLIContext(t *testing.T, flags []cli.Flag, args ...string) *cli.Context {
	t.Helper()

	set := flag.NewFlagSet("test", flag.ContinueOnError)
	for _, f := range flags {
		require.NoError(t, f.Apply(set))
	}

	require.NoError(t, set.Parse(args))

	return cli.NewContext(cli.NewApp(), set, nil)
}

// writeFakeSpoc writes a spoc script into a new directory, which exits with
// the given code, and returns the directory.
func writeFakeSpoc(t *testing.T, exitCode string) string {
	t.Helper()

	dir := t.TempDir()
	// The PATH holds only the fake, so it uses shell builtins only.
	script := "#!/bin/sh\necho \"spoc $@\"\n" +
		"while IFS= read -r line; do echo \"$line\"; done\nexit " + exitCode + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, spocCmd), []byte(script), 0o755))

	return dir
}

func TestRunSpoc(t *testing.T) {
	for name, tc := range map[string]struct {
		exitCode string
		wantCode int
	}{
		"success": {exitCode: "0"},
		"failure": {exitCode: "3", wantCode: 3},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PATH", writeFakeSpoc(t, tc.exitCode))

			stdout := &bytes.Buffer{}
			err := runSpoc(
				t.Context(),
				[]string{"merge", "--check"},
				strings.NewReader("stdin\n"),
				stdout,
				&bytes.Buffer{},
			)
			// The input is passed through, like a password for --password-stdin.
			require.Equal(t, "spoc merge --check\nstdin\n", stdout.String())

			if tc.wantCode == 0 {
				require.NoError(t, err)

				return
			}

			// The exit code of spoc becomes the one of the operator binary.
			exitCoder, ok := err.(cli.ExitCoder) //nolint:errorlint // cli.Exit is not wrapped
			require.True(t, ok, "%T", err)
			require.Equal(t, tc.wantCode, exitCoder.ExitCode())
		})
	}

	t.Run("missing binary", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		err := runSpoc(t.Context(), nil, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		require.Error(t, err)

		_, isExitCoder := err.(cli.ExitCoder) //nolint:errorlint // cli.Exit is not wrapped
		require.False(t, isExitCoder)
		require.ErrorContains(t, err, "running spoc")
	})
}

func TestGetEnabledControllers(t *testing.T) {
	t.Parallel()

	flags := daemonCommand(&version.Info{}).Flags

	names := func(args ...string) []string {
		controllers := getEnabledControllers(newCLIContext(t, flags, args...))

		res := make([]string, 0, len(controllers))
		for _, c := range controllers {
			res = append(res, c.Name())
		}

		return res
	}

	require.Equal(t, []string{"seccomp-spod"}, names())
	require.Empty(t, names("--with-seccomp=false"))
	require.Equal(t, []string{"seccomp-spod", "recorder-spod"}, names("--with-recording"))
	require.Equal(t, []string{"seccomp-spod", "selinuxprofile-spod"}, names("--with-selinux"))
	require.Equal(t,
		[]string{"seccomp-spod", "selinuxprofile-spod", "rawselinuxprofile-spod"},
		names("--with-selinux", "--with-raw-selinux"),
	)
	require.Equal(t, []string{"seccomp-spod"}, names("--with-raw-selinux"),
		"raw SELinux profiles require SELinux")
	require.Equal(t, []string{"seccomp-spod", "apparmor-spod"}, names("--with-apparmor"))
}

func TestDaemonCacheOptions(t *testing.T) {
	t.Parallel()

	// byObject returns the options of the objects of the type of obj.
	byObject := func(opts cache.Options, obj client.Object) (cache.ByObject, bool) {
		t.Helper()

		for o, byObject := range opts.ByObject {
			if reflect.TypeOf(o) == reflect.TypeOf(obj) {
				return byObject, true
			}
		}

		return cache.ByObject{}, false
	}

	podOptions := func(opts cache.Options) cache.ByObject {
		t.Helper()

		byPod, ok := byObject(opts, &corev1.Pod{})
		require.True(t, ok)

		return byPod
	}

	opts := cache.Options{}
	setDaemonCacheOptions(&opts, "node", false)
	require.Equal(t, &daemonSyncPeriod, opts.SyncPeriod)
	require.Nil(t, opts.DefaultLabelSelector)
	require.Len(t, opts.ByObject, 2)
	require.Equal(t, fields.OneTermEqualSelector("spec.nodeName", "node"), podOptions(opts).Field)
	require.Nil(t, podOptions(opts).Label)

	byStatus, ok := byObject(opts, &secprofnodestatusv1.SecurityProfileNodeStatus{})
	require.True(t, ok, "only the node statuses of the node are cached")
	require.Nil(t, byStatus.Field)
	require.True(
		t,
		byStatus.Label.Matches(labels.Set{secprofnodestatusv1.StatusToNodeLabel: "node"}),
	)
	require.False(
		t,
		byStatus.Label.Matches(labels.Set{secprofnodestatusv1.StatusToNodeLabel: "other"}),
	)
	require.False(t, byStatus.Label.Matches(labels.Set{}))

	// Long node names are hashed in the label value, like the node status
	// client does.
	longName := strings.Repeat("n", 100)
	opts = cache.Options{}
	setDaemonCacheOptions(&opts, longName, false)
	byStatus, ok = byObject(opts, &secprofnodestatusv1.SecurityProfileNodeStatus{})
	require.True(t, ok)
	require.True(t, byStatus.Label.Matches(labels.Set{
		secprofnodestatusv1.StatusToNodeLabel: util.NodeNameLabelValue(longName),
	}))

	opts = cache.Options{}
	setDaemonCacheOptions(&opts, "", true)
	require.Len(t, opts.ByObject, 1, "without a node name every node status is cached")
	require.Nil(t, podOptions(opts).Field, "without a node name every pod is cached")
	require.Equal(t,
		labels.SelectorFromSet(labels.Set{bindata.EnableRecordingLabel: "true"}),
		podOptions(opts).Label,
	)
}

// The daemon creates its cache before it sets up the controllers, so the
// scheme has to know the node status kind by then.
func TestDaemonCacheOptionsCreateCache(t *testing.T) {
	t.Parallel()

	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(corev1.SchemeGroupVersion.WithKind("Pod"), meta.RESTScopeNamespace)
	mapper.Add(
		secprofnodestatusv1.GroupVersion.WithKind("SecurityProfileNodeStatus"),
		meta.RESTScopeNamespace,
	)

	newCache := func(scheme *runtime.Scheme) error {
		opts := cache.Options{Scheme: scheme, Mapper: mapper}
		setDaemonCacheOptions(&opts, "node", true)

		_, err := cache.New(&rest.Config{Host: "https://127.0.0.1:1"}, opts)

		return err
	}

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.Error(t, newCache(scheme))

	require.NoError(t, secprofnodestatusv1.AddToScheme(scheme))
	require.NoError(t, newCache(scheme))
}

func TestNewDaemonCache(t *testing.T) {
	t.Setenv(config.NodeNameEnvKey, "node")

	flags := daemonCommand(&version.Info{}).Flags
	require.NotNil(t, newDaemonCache(newCLIContext(t, flags, "--with-mem-optim")))
}

func TestNewTLSConfig(t *testing.T) {
	t.Parallel()

	modern := *configv1.TLSProfiles[configv1.TLSProfileModernType]

	for name, tc := range map[string]struct {
		isOpenShift    bool
		policy         configv1.TLSAdherencePolicy
		wantMinVersion uint16
		wantCiphers    bool
	}{
		"kubernetes": {wantMinVersion: tlsVersion12},
		"openshift honors the cluster profile": {
			isOpenShift: true, policy: configv1.TLSAdherencePolicyStrictAllComponents,
			wantMinVersion: tlsVersion13,
		},
		"openshift default profile": {
			isOpenShift: true, policy: configv1.TLSAdherencePolicyNoOpinion,
			wantMinVersion: tlsVersion12, wantCiphers: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := newTLSConfig(tc.isOpenShift, modern, tc.policy)
			require.Equal(t, tc.isOpenShift, cfg.isOpenShift)
			require.Equal(t, tc.policy, cfg.adherencePolicy)
			require.Equal(t, modern, cfg.profile)

			c := applyTLSOptions(&cfg)
			require.Equal(t, []string{"http/1.1"}, c.NextProtos, "HTTP/2 is always disabled")
			require.Equal(t, tc.wantMinVersion, c.MinVersion)
			require.Equal(t, tc.wantCiphers, len(c.CipherSuites) > 0)
		})
	}
}

func TestGetJsonEnricher(t *testing.T) {
	t.Parallel()

	flags := jsonEnricherCommand(&version.Info{}).Flags

	jsonEnricher, err := getJsonEnricher(newCLIContext(t, flags,
		"--audit-log-interval-seconds=5", "--audit-log-maxsize=10",
	), &version.Info{})
	require.NoError(t, err)
	require.NotNil(t, jsonEnricher)

	_, err = getJsonEnricher(newCLIContext(t, flags, "--enricher-filters-json={"), &version.Info{})
	require.Error(t, err)
}

// fakeReadyzManager records the readiness checks.
type fakeReadyzManager struct {
	checks map[string]healthz.Checker
	cache  cache.Cache
	err    error
}

func (m *fakeReadyzManager) AddReadyzCheck(name string, check healthz.Checker) error {
	if m.err != nil {
		return m.err
	}

	m.checks[name] = check

	return nil
}

func (m *fakeReadyzManager) GetCache() cache.Cache { return m.cache }

// syncedCache is an informer cache whose sync state the test controls. The
// check only waits for the sync, so the other methods are not implemented.
type syncedCache struct {
	cache.Cache

	synced bool
}

func (c *syncedCache) WaitForCacheSync(context.Context) bool { return c.synced }

func TestAddCacheSyncReadyzCheck(t *testing.T) {
	t.Parallel()

	informers := &syncedCache{}
	mgr := &fakeReadyzManager{checks: map[string]healthz.Checker{}, cache: informers}
	require.NoError(t, addCacheSyncReadyzCheck(mgr))

	check := mgr.checks["cache-sync"]
	require.NotNil(t, check)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", http.NoBody)
	require.NoError(t, err)
	require.Error(t, check(req), "not ready while the caches are not synced")

	informers.synced = true

	require.NoError(t, check(req))

	failing := &fakeReadyzManager{err: errTest}
	require.ErrorIs(t, addCacheSyncReadyzCheck(failing), errTest)
}

func TestProfilingEndpoint(t *testing.T) {
	t.Parallel()

	require.Equal(t, "127.0.0.1:6060", profilingEndpoint("", 6060))
	require.Equal(t, "127.0.0.1:6061", profilingEndpoint(config.DefaultProfilingAddress, 6061))
	require.Equal(t, "0.0.0.0:6060", profilingEndpoint(config.AllInterfacesAddress, 6060))
	require.Equal(t, "[::1]:6060", profilingEndpoint("::1", 6060))
	require.Equal(t, "[::]:6060", profilingEndpoint("::", 6060))
	require.Equal(t, "[::1]:6060", profilingEndpoint("[::1]", 6060))

	var address string

	for _, f := range globalFlags() {
		if sf, ok := f.(*cli.StringFlag); ok && sf.Name == profilingAddressFlag {
			address = sf.Value
		}
	}

	require.Equal(
		t,
		config.DefaultProfilingAddress,
		address,
		"profiling binds to loopback per default",
	)
}

func TestManagerMaxConcurrentReconcilesFlag(t *testing.T) {
	t.Parallel()

	flags := managerCommand(&version.Info{}).Flags
	require.Equal(t, 4, newCLIContext(t, flags).Int(maxConcurrentReconcilesFlag))
	require.Equal(
		t,
		8,
		newCLIContext(t, flags, "--max-concurrent-reconciles=8").Int(maxConcurrentReconcilesFlag),
	)
}

func TestManagerKubeAPIRateLimitFlags(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		args      []string
		wantQPS   float32
		wantBurst int
	}{
		{
			// The controller-runtime disables the client side rate limit.
			name:    "unset",
			wantQPS: -1,
		},
		{
			name:    "burst without qps",
			args:    []string{"--kube-api-burst=100"},
			wantQPS: -1,
		},
		{
			name:    "qps",
			args:    []string{"--kube-api-qps=50"},
			wantQPS: 50,
		},
		{
			name:      "qps and burst",
			args:      []string{"--kube-api-qps=50", "--kube-api-burst=100"},
			wantQPS:   50,
			wantBurst: 100,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Applying a flag sets its default, so every parallel test case
			// needs its own flags.
			flags := managerCommand(&version.Info{}).Flags
			ctx := newCLIContext(t, flags, tc.args...)
			cfg := &rest.Config{QPS: -1}
			setKubeAPIRateLimit(cfg, ctx.Float64(kubeAPIQPSFlag), ctx.Int(kubeAPIBurstFlag))
			require.InDelta(t, tc.wantQPS, cfg.QPS, 0)
			require.Equal(t, tc.wantBurst, cfg.Burst)
		})
	}
}

// The spoc command passes every argument after its name to spoc, flags
// included, wherever global flags precede it.
func TestSpocCommandPassesArguments(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" > \"$SPOC_ARGS_FILE\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, spocCmd), []byte(script), 0o755))
	t.Setenv("PATH", dir)
	t.Setenv("SPOC_ARGS_FILE", argsFile)

	for _, args := range [][]string{
		{config.OperatorName, spocCmd, "merge", "--check", "-o", "out.yaml"},
		{config.OperatorName, "--verbosity", "1", spocCmd, "merge", "--check", "-o", "out.yaml"},
		{config.OperatorName, "s", "merge", "--check", "-o", "out.yaml"},
	} {
		require.NoError(t, os.WriteFile(argsFile, nil, 0o600))

		app := newApp()
		app.ExitErrHandler = func(*cli.Context, error) {}
		require.NoError(t, app.Run(args), args)

		got, err := os.ReadFile(argsFile)
		require.NoError(t, err)
		require.Equal(t, "merge --check -o out.yaml\n", string(got), args)
	}
}
