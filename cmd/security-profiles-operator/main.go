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
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // required for profiling
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/urfave/cli/v2"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	apparmorprofilev1 "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingv1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingv1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofilev1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofilev1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/cmd"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/selinuxprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/bindingtracker"
	nodestatus "sigs.k8s.io/security-profiles-operator/internal/pkg/manager/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingtracker"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadannotator"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/clidocs"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/execmetadata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/validation"
)

const (
	spocCmd                      string = "spoc"
	nodeStatusControllerFlag     string = "with-nodestatus-controller"
	spodControllerFlag           string = "with-spod-controller"
	workloadAnnotatorFlag        string = "with-workload-annotator"
	recordingMergerFlag          string = "with-recording-merger"
	recordingTrackerFlag         string = "with-recording-tracker"
	bindingTrackerFlag           string = "with-binding-tracker"
	recordingFlag                string = "with-recording"
	seccompFlag                  string = "with-seccomp"
	selinuxFlag                  string = "with-selinux"
	apparmorFlag                 string = "with-apparmor"
	rawSelinuxFlag               string = "with-raw-selinux"
	webhookFlag                  string = "webhook"
	memOptimFlag                 string = "with-mem-optim"
	insecureMetricsAccessFlag    string = "with-insecure-metrics-access"
	maxConcurrentReconcilesFlag  string = "max-concurrent-reconciles"
	maxMetricSeriesFlag          string = "max-metric-series"
	profilingAddressFlag         string = "profiling-address"
	defaultWebhookPort           int    = 9443
	metricsPort                  int    = 8443
	auditLogIntervalSecondsParam string = "audit-log-interval-seconds"
	auditLogPathParam            string = "audit-log-path"
	auditLogMaxSizeParam         string = "audit-log-maxsize"
	// The plural form is not used for audit-log-file-maxbackup to match the k8s api server audit log options.
	auditLogMaxBackupParam   string = "audit-log-maxbackup"
	auditLogMaxAgeParam      string = "audit-log-maxage"
	enricherFiltersJsonParam string = "enricher-filters-json"
	enricherLogSourceParam   string = "enricher-log-source"
	// Deprecated: TLS version is now managed via OpenShift TLS profiles.
	tlsMinVersionParam string = "tls-min-version"

	// defaultTrue is the default text of the boolean flags which default to
	// true.
	defaultTrue string = "true"

	// cacheSyncCheckTimeout bounds a single readiness check, so that it polls
	// the informer caches rather than waiting for them.
	cacheSyncCheckTimeout time.Duration = 5 * time.Second
)

var (
	// daemonSyncPeriod is the resync period of the daemon cache. The manager
	// and the webhook use the default of controller-runtime, because every
	// resync reconciles all objects of the cluster there.
	daemonSyncPeriod = time.Second * 30
	setupLog         = ctrl.Log.WithName("setup")

	// ErrTLSConfigChanged is returned when TLS configuration has changed and requires a restart.
	ErrTLSConfigChanged = errors.New("TLS configuration changed, restart required")
)

// runtimeEnvVars are the environment variables the operator reads which are
// not bound to a flag. The deployment sets them.
var runtimeEnvVars = []clidocs.EnvVar{
	{
		Name:        config.NodeNameEnvKey,
		Description: "name of the node, required by daemon, bpf-recorder and non-root-enabler",
	},
	{
		Name:        config.PodNameEnvKey,
		Description: "name of the pod of the daemon, required for SELinux",
	},
	{
		Name:        config.SPOdNameEnvKey,
		Description: "name of the `SecurityProfilesOperatorDaemon` of the daemon",
	},
	{
		Name:        config.OperatorNamespaceEnvKey,
		Description: "namespace of the operator",
	},
	{
		Name: config.RestrictNamespaceEnvKey,
		Description: "restricts manager and daemon to the comma separated namespaces, " +
			"the namespace of the operator is always included",
	},
	{
		Name:        "WATCH_NAMESPACE",
		Description: "used like `" + config.RestrictNamespaceEnvKey + "` if that is not set",
	},
	{
		Name: config.KubeletDirEnvKey,
		Description: "kubelet root directory, used when the kubelet configuration written by the " +
			"non-root-enabler has none, defaults to `" + config.DefaultKubeletPath + "`",
	},
	{
		Name: strings.Join([]string{
			config.EnableLogEnricherEnvKey,
			config.EnableJsonEnricherEnvKey,
			config.EnableBpfRecorderEnvKey,
		}, ", "),
		Description: "enable the respective daemon container in addition to the " +
			"`SecurityProfilesOperatorDaemon` configuration, the manager passes them on to the daemon",
	},
	{
		Name: config.EnableInsecureMetricsAccessEnvKey,
		Description: "read by the manager as well: allows unauthenticated access to the metrics " +
			"endpoint of the daemon in addition to the `SecurityProfilesOperatorDaemon` configuration",
	},
	{
		Name:        config.MaxMetricSeriesEnvKey,
		Description: "read by the manager as well: passed on to the daemon if set",
	},
	{
		Name: "RELATED_IMAGE_SELINUXD",
		Description: "image of the selinuxd container of the daemon if the image mapping of the " +
			"operator ConfigMap selects none for the operating system of the node",
	},
	{
		Name: "RELATED_IMAGE_SELINUXD_EL8, RELATED_IMAGE_SELINUXD_EL9, " +
			"RELATED_IMAGE_SELINUXD_EL10, RELATED_IMAGE_SELINUXD_FEDORA",
		Description: "images of the selinuxd container per operating system of the node, " +
			"which the `" + util.SelinuxdImageMappingKey + "` mapping of the operator ConfigMap refers to, " +
			"an unset one falls back to RELATED_IMAGE_SELINUXD",
	},
}

func main() {
	if err := newApp().RunContext(context.Background(), os.Args); err != nil {
		// Check if this is a TLS configuration change requiring restart
		if errors.Is(err, ErrTLSConfigChanged) {
			os.Exit(0) // intentional exit to trigger pod restart
		}

		// The logger only exists once a command initialized it, errors of
		// the flag parsing come before.
		if loggingInitialized {
			setupLog.Error(err, "running security-profiles-operator")
		} else {
			fmt.Fprintln(os.Stderr, "running security-profiles-operator:", err)
		}

		os.Exit(1)
	}
}

// newApp returns the command line application of the operator.
func newApp() *cli.App {
	app, info := cmd.DefaultApp()
	app.Name = config.OperatorName
	app.Usage = "Kubernetes Security Profiles Operator"
	app.Description = "The Security Profiles Operator makes it easier for cluster admins " +
		"to manage their seccomp or AppArmor profiles and apply them to Kubernetes' workloads."

	app.Commands = append(app.Commands,
		managerCommand(info),
		daemonCommand(info),
		webhookCommand(info),
		nonRootEnablerCommand(info),
		logEnricherCommand(info),
		jsonEnricherCommand(info),
		bpfRecorderCommand(info),
		spocCommand(),
		clidocs.Command(newApp, runtimeEnvVars),
	)

	app.Flags = globalFlags()

	// Every command which starts the profiling server in initialize runs
	// before this.
	app.After = func(*cli.Context) error {
		shutdownProfiling()

		return nil
	}

	return app
}

// enabledByDefault returns a boolean flag which is true unless it is set to
// false.
func enabledByDefault(name, usage string, aliases ...string) *cli.BoolFlag {
	return &cli.BoolFlag{
		Name:        name,
		Aliases:     aliases,
		Value:       true,
		DefaultText: defaultTrue,
		Usage:       usage,
	}
}

func managerCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "manager",
		Aliases: []string{"m"},
		Usage:   "run the manager",
		Action: func(ctx *cli.Context) error {
			return runManager(ctx, info)
		},
		Flags: []cli.Flag{
			enabledByDefault(webhookFlag, "manage the Kubernetes resources of the webhook", "w"),
			enabledByDefault(nodeStatusControllerFlag, "enable the node status controller"),
			enabledByDefault(spodControllerFlag, "enable the SPOD controller"),
			enabledByDefault(workloadAnnotatorFlag, "enable the workload annotator"),
			enabledByDefault(recordingMergerFlag, "enable the recording merger"),
			enabledByDefault(recordingTrackerFlag, "enable the recording tracker"),
			enabledByDefault(bindingTrackerFlag, "enable the binding tracker"),
			&cli.IntFlag{
				Name:  maxConcurrentReconcilesFlag,
				Value: controller.DefaultMaxConcurrentReconciles,
				Usage: "the number of concurrent reconciles of the pod driven controllers",
			},
		},
	}
}

func daemonCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "daemon",
		Aliases: []string{"d"},
		Usage:   "run the daemon",
		Action: func(ctx *cli.Context) error {
			return runDaemon(ctx, info)
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        seccompFlag,
				Usage:       "listen for seccomp API resources",
				Value:       true,
				DefaultText: defaultTrue,
				EnvVars:     []string{config.EnableSeccompEnvKey},
			},
			&cli.BoolFlag{
				Name:    selinuxFlag,
				Usage:   "listen for SELinux API resources",
				Value:   false,
				EnvVars: []string{config.EnableSelinuxEnvKey},
			},
			&cli.BoolFlag{
				Name:    apparmorFlag,
				Usage:   "listen for AppArmor API resources",
				Value:   false,
				EnvVars: []string{config.EnableApparmorEnvKey},
			},
			&cli.BoolFlag{
				Name:    rawSelinuxFlag,
				Usage:   "listen for RawSelinuxProfile API resources",
				Value:   false,
				EnvVars: []string{config.EnableRawSelinuxEnvKey},
			},
			&cli.BoolFlag{
				Name:    recordingFlag,
				Usage:   "listen for ProfileRecording API resources",
				Value:   false,
				EnvVars: []string{config.EnableRecordingEnvKey},
			},
			&cli.BoolFlag{
				Name:    memOptimFlag,
				Usage:   "enable memory optimization by watching only labeled pods",
				Value:   false,
				EnvVars: []string{config.EnableMemOptimEnvKey},
			},
			&cli.BoolFlag{
				Name:    insecureMetricsAccessFlag,
				Usage:   "allow unauthenticated access to the metrics endpoint",
				Value:   false,
				EnvVars: []string{config.EnableInsecureMetricsAccessEnvKey},
			},
			&cli.IntFlag{
				Name: maxMetricSeriesFlag,
				Usage: "number of series each per workload metric keeps at most, " +
					"increments of further series get dropped, 0 keeps any number",
				Value:   metrics.DefaultMaxSeries,
				EnvVars: []string{config.MaxMetricSeriesEnvKey},
			},
		},
	}
}

func webhookCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "webhook",
		Aliases: []string{"w"},
		Usage:   "run the webhook",
		Action: func(ctx *cli.Context) error {
			return runWebhook(ctx, info)
		},
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   defaultWebhookPort,
				Usage:   "the port on which to expose the webhook service",
			},
			&cli.BoolFlag{
				Name:    "static",
				Aliases: []string{"s"},
				Value:   false,
				Usage:   "the Kubernetes resources of the webhook are managed statically",
			},
			&cli.StringFlag{
				Name:   tlsMinVersionParam,
				Hidden: true,
				Usage:  "deprecated and ignored, the TLS configuration is managed through OpenShift TLS profiles",
			},
		},
	}
}

func nonRootEnablerCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before: initialize,
		Name:   "non-root-enabler",
		Usage:  "run the non root enabler",
		Action: func(ctx *cli.Context) error {
			return runNonRootEnabler(ctx, info)
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "runtime",
				Aliases: []string{"r"},
				Value:   "",
				Usage:   "the container runtime in the cluster (cri-o, containerd or docker), only logged",
			},
			&cli.BoolFlag{
				Name:    "apparmor",
				Aliases: []string{"a"},
				Usage:   "install the AppArmor profiles of the operator",
				EnvVars: []string{config.AppArmorEnvKey},
			},
		},
	}
}

func logEnricherCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "log-enricher",
		Aliases: []string{"l"},
		Usage:   "run the audit log enricher",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  enricherFiltersJsonParam,
				Value: "",
				Usage: "the filters of the log enricher as inline JSON",
			},
			&cli.StringFlag{
				Name:  enricherLogSourceParam,
				Value: "",
				Usage: "the log source to ingest (`Bpf` or `Auditd`)",
			},
		},
		Action: func(ctx *cli.Context) error {
			return runLogEnricher(ctx, info)
		},
	}
}

func jsonEnricherCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "json-enricher",
		Aliases: []string{"j"},
		Usage:   "run the JSON audit log enricher",
		Action: func(ctx *cli.Context) error {
			return runJsonEnricher(ctx, info)
		},
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    auditLogIntervalSecondsParam,
				Aliases: []string{"a"},
				Value:   60,
				Usage:   "the audit log interval of the JSON enricher in seconds",
			},
			&cli.StringFlag{
				Name:        auditLogPathParam,
				Value:       "",
				DefaultText: "stdout",
				Usage:       "the audit log file path of the JSON enricher",
			},
			&cli.IntFlag{
				Name:  auditLogMaxBackupParam,
				Value: 0,
				Usage: "the maximum number of old audit log files of the JSON enricher to retain, " +
					"0 retains all if a maximum age is set and 10 otherwise",
			},
			&cli.IntFlag{
				Name:  auditLogMaxSizeParam,
				Value: 100,
				Usage: "the maximum size in megabytes of the audit log file of the JSON enricher " +
					"before it gets rotated",
			},
			&cli.IntFlag{
				Name:  auditLogMaxAgeParam,
				Value: 0,
				Usage: "the maximum number of days to retain old audit log files of the JSON enricher, " +
					"based on the timestamp in their file name, 0 retains them regardless of age",
			},
			&cli.StringFlag{
				Name:  enricherFiltersJsonParam,
				Value: "",
				Usage: "the filters of the JSON enricher as inline JSON",
			},
		},
	}
}

func bpfRecorderCommand(info *version.Info) *cli.Command {
	return &cli.Command{
		Before:  initialize,
		Name:    "bpf-recorder",
		Aliases: []string{"b"},
		Usage:   "run the bpf recorder",
		Action: func(ctx *cli.Context) error {
			return runBPFRecorder(ctx, info)
		},
	}
}

func spocCommand() *cli.Command {
	return &cli.Command{
		Name:    spocCmd,
		Aliases: []string{"s"},
		Usage:   "run the CLI",
		Action:  runCLI,
		// All arguments, including the flags, belong to spoc.
		SkipFlagParsing: true,
		HideHelp:        true,
	}
}

func globalFlags() []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{
			Name:    "verbosity",
			Aliases: []string{"V"},
			Usage:   "the logging verbosity to be used",
			Value:   0,
			EnvVars: []string{config.VerbosityEnvKey},
		},
		&cli.BoolFlag{
			Name:    "profiling",
			Aliases: []string{"p"},
			Usage:   "enable profiling support",
			EnvVars: []string{config.ProfilingEnvKey},
		},
		&cli.UintFlag{
			Name:    "profiling-port",
			Usage:   "the profiling port to be used",
			Value:   config.DefaultProfilingPort,
			EnvVars: []string{config.ProfilingPortEnvKey},
		},
		&cli.StringFlag{
			Name:    profilingAddressFlag,
			Usage:   "the address the profiling endpoint binds to",
			Value:   config.DefaultProfilingAddress,
			EnvVars: []string{config.ProfilingAddressEnvKey},
		},
	}
}

func initialize(ctx *cli.Context) error {
	if err := initLogging(ctx); err != nil {
		return fmt.Errorf("init logging: %w", err)
	}

	initProfiling(ctx)

	return nil
}

// loggingInitialized is set once initLogging set the logger.
var loggingInitialized bool

func initLogging(ctx *cli.Context) error {
	logConfig := textlogger.NewConfig()
	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	loggingInitialized = true

	set := flag.NewFlagSet("logging", flag.ContinueOnError)
	klog.InitFlags(set)

	level := ctx.Int("verbosity")
	if err := set.Parse([]string{fmt.Sprintf("-v=%d", level)}); err != nil {
		return fmt.Errorf("parse verbosity flag: %w", err)
	}

	if err := logConfig.Verbosity().Set(strconv.FormatInt(int64(level), 10)); err != nil {
		return fmt.Errorf("setting the verbosity flag to level %d: %w", level, err)
	}

	ctrl.Log.Info(fmt.Sprintf("Set logging verbosity to %d", level))

	return nil
}

var profilingServer *http.Server

func initProfiling(ctx *cli.Context) {
	enabled := ctx.Bool("profiling")
	ctrl.Log.Info(fmt.Sprintf("Profiling support enabled: %v", enabled))

	if enabled {
		endpoint := profilingEndpoint(ctx.String(profilingAddressFlag), ctx.Uint("profiling-port"))

		ctrl.Log.Info("Starting profiling server", "endpoint", endpoint)

		profilingServer = &http.Server{
			Addr:              endpoint,
			ReadHeaderTimeout: util.DefaultReadHeaderTimeout,
		}
		go func() {
			if err := profilingServer.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				ctrl.Log.Error(err, "unable to run profiling server")
			}
		}()
	}
}

// profilingEndpoint returns the listen address of the profiling server. The
// default address is the loopback interface, so that the unauthenticated
// endpoint is not reachable from the pod network unless asked for. IPv6
// addresses get enclosed in brackets, unless they are already.
func profilingEndpoint(address string, port uint) string {
	if address == "" {
		address = config.DefaultProfilingAddress
	}

	address = strings.TrimSuffix(strings.TrimPrefix(address, "["), "]")

	return net.JoinHostPort(address, strconv.FormatUint(uint64(port), 10))
}

func shutdownProfiling() {
	if profilingServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ctrl.Log.Info("Shutting down profiling server")

		if err := profilingServer.Shutdown(shutdownCtx); err != nil {
			ctrl.Log.Error(err, "unable to shut down profiling server")
		}
	}
}

func printInfo(component string, info *version.Info) {
	setupLog.Info(
		"starting component: "+component,
		info.AsKeyValues()...,
	)
}

func manageWebhook(ctx *cli.Context) bool {
	return ctx.Bool(webhookFlag)
}

func runManager(ctx *cli.Context, info *version.Info) error {
	printInfo("security-profiles-operator", info)

	cfg, tlsCfg, err := clusterConfig(ctx.Context)
	if err != nil {
		return err
	}

	operatorNamespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("get operator namespace: %w", err)
	}

	gracefulShutdownTimeout := 30 * time.Second
	ctrlOpts := manager.Options{
		Cache: cache.Options{
			DefaultTransform: cache.TransformStripManagedFields(),
		},
		LeaderElection:                true,
		LeaderElectionID:              "security-profiles-operator-lock",
		LeaderElectionReleaseOnCancel: true,
		HealthProbeBindAddress:        fmt.Sprintf(":%d", config.HealthProbePort),
		GracefulShutdownTimeout:       &gracefulShutdownTimeout,
		Metrics:                       secureMetricsOptions(&tlsCfg),
	}

	served, err := setRESTMapper(&ctrlOpts, cfg)
	if err != nil {
		return err
	}

	setControllerOptionsForNamespaces(&ctrlOpts, operatorNamespace)
	restrictOperandCache(&ctrlOpts, operatorNamespace, served)

	// The manager uses the default scheme, which has to know the kinds of the
	// cache options before the manager creates the cache.
	if err := addToScheme(clientgoscheme.Scheme,
		schemeAPI{"certmanager", certmanagerv1.AddToScheme},
		schemeAPI{"profilebinding v1", profilebindingv1.AddToScheme},
		schemeAPI{"profilerecording v1", profilerecordingv1.AddToScheme},
		schemeAPI{"seccompprofile v1", seccompprofilev1.AddToScheme},
		schemeAPI{"apparmorprofile v1", apparmorprofilev1.AddToScheme},
		schemeAPI{"selinuxprofile v1", selinuxprofilev1.AddToScheme},
		schemeAPI{"ServiceMonitor", monitoringv1.AddToScheme},
	); err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create cluster manager: %w", err)
	}

	if err := addCacheSyncReadyzCheck(mgr); err != nil {
		return err
	}

	enabledControllers := []controller.Controller{}

	if ctx.Bool(nodeStatusControllerFlag) {
		enabledControllers = append(enabledControllers, nodestatus.NewController())
	}

	if ctx.Bool(spodControllerFlag) {
		enabledControllers = append(enabledControllers, spod.NewController())
	}

	if ctx.Bool(workloadAnnotatorFlag) {
		enabledControllers = append(enabledControllers, workloadannotator.NewController())
	}

	if ctx.Bool(recordingMergerFlag) {
		enabledControllers = append(enabledControllers, recordingmerger.NewController())
	}

	if ctx.Bool(recordingTrackerFlag) {
		enabledControllers = append(enabledControllers, recordingtracker.NewController())
	}

	if ctx.Bool(bindingTrackerFlag) {
		enabledControllers = append(enabledControllers, bindingtracker.NewController())
	}

	setupLog.Info("enabled controllers", "controllers", enabledControllers)

	setupCtx := controller.WithMaxConcurrentReconciles(
		context.WithValue(ctx.Context, spod.ManageWebhookKey, manageWebhook(ctx)),
		ctx.Int(maxConcurrentReconcilesFlag),
	)

	if err := setupEnabledControllers(setupCtx, enabledControllers, mgr, nil); err != nil {
		return fmt.Errorf("enable controllers: %w", err)
	}

	sigHandler := ctrl.SetupSignalHandler()

	return setupManagerWithTLSWatcher(
		sigHandler, mgr, &tlsCfg, "manager",
	)
}

// setControllerOptionsForNamespaces restricts the cache to the watched
// namespaces and the operator namespace, if the watched namespaces are
// restricted.
func setControllerOptionsForNamespaces(opts *ctrl.Options, operatorNS string) {
	namespace, ok := os.LookupEnv(config.RestrictNamespaceEnvKey)
	if !ok {
		namespace = os.Getenv("WATCH_NAMESPACE")
	}

	// Supports multiple namespaces set in WATCH_NAMESPACE (e.g ns1,ns2).
	// This is not intended to be used for excluding namespaces, which is better
	// done via a predicate. A high number of namespaces may cause performance
	// issues.
	namespaces := watchNamespaces(namespace, operatorNS)
	if len(namespaces) == 0 {
		setupLog.Info("watching all namespaces")

		return
	}

	opts.Cache.DefaultNamespaces = make(map[string]cache.Config, len(namespaces))
	for _, ns := range namespaces {
		opts.Cache.DefaultNamespaces[ns] = cache.Config{}
	}

	setupLog.Info("watching namespaces", "namespaces", namespaces)
}

// watchNamespaces returns the namespaces of the comma separated list, always
// including the operator namespace, because the operator has to read its own
// configuration. An empty list means that all namespaces are watched.
func watchNamespaces(namespaces, operatorNamespace string) []string {
	if namespaces == "" {
		return nil
	}

	var res []string

	for ns := range strings.SplitSeq(namespaces, ",") {
		ns = strings.TrimSpace(ns)
		if ns == "" || slices.Contains(res, ns) {
			continue
		}

		res = append(res, ns)
	}

	if operatorNamespace != "" && !slices.Contains(res, operatorNamespace) {
		res = append(res, operatorNamespace)
	}

	return res
}

// servedAPIs are the optional APIs which the cluster serves.
type servedAPIs struct {
	admissionPolicies bool
	certManager       bool
}

// setRESTMapper sets the REST mapper of the manager and returns which of the
// optional APIs the cluster serves. The cache options depend on that, so it
// has to be known before the manager gets created. The manager and the SPOD
// controller share the mapper, so they come to the same conclusion.
func setRESTMapper(opts *ctrl.Options, cfg *rest.Config) (servedAPIs, error) {
	var served servedAPIs

	httpClient, err := rest.HTTPClientFor(cfg)
	if err != nil {
		return served, fmt.Errorf("create HTTP client: %w", err)
	}

	mapper, err := apiutil.NewDynamicRESTMapper(cfg, httpClient)
	if err != nil {
		return served, fmt.Errorf("create REST mapper: %w", err)
	}

	served.admissionPolicies, err = spod.ServesAdmissionPolicies(mapper)
	if err != nil {
		return served, fmt.Errorf("discover the admission policy API: %w", err)
	}

	served.certManager, err = spod.ServesCertManager(mapper)
	if err != nil {
		return served, fmt.Errorf("discover the cert-manager API: %w", err)
	}

	opts.MapperProvider = func(*rest.Config, *http.Client) (meta.RESTMapper, error) {
		return mapper, nil
	}

	return served, nil
}

// restrictOperandCache limits the cache of the operand kinds to the operator
// namespace. The operator creates them only there and its RBAC permissions are
// scoped to that namespace, so a cluster wide informer would not be allowed to
// list them. The cluster scoped operands are cached by name for the same
// reason, and the pods, which every namespace can hold, are stripped down to
// the fields the controllers read. The admission policies and the cert-manager
// resources are only added if the cluster serves their API, because creating
// the cache fails for kinds without a REST mapping. The webhook configurations
// are served by every supported Kubernetes version.
func restrictOperandCache(
	opts *ctrl.Options,
	operatorNamespace string,
	served servedAPIs,
) {
	if opts.Cache.ByObject == nil {
		opts.Cache.ByObject = map[client.Object]cache.ByObject{}
	}

	namespaced := []client.Object{
		&appsv1.DaemonSet{},
		&appsv1.Deployment{},
		&corev1.Service{},
		&policyv1.PodDisruptionBudget{},
	}

	if served.certManager {
		namespaced = append(namespaced, &certmanagerv1.Issuer{}, &certmanagerv1.Certificate{})
	}

	for _, obj := range namespaced {
		opts.Cache.ByObject[obj] = cache.ByObject{
			Namespaces: map[string]cache.Config{operatorNamespace: {}},
		}
	}

	// A list or watch with a metadata.name field selector is authorized like
	// a get of that name, so the RBAC of these kinds carries the names.
	byName := map[client.Object]string{
		&admissionregv1.MutatingWebhookConfiguration{}:   bindata.MutatingWebhookConfigName,
		&admissionregv1.ValidatingWebhookConfiguration{}: bindata.ValidatingWebhookConfigName,
	}

	if served.admissionPolicies {
		byName[&admissionregv1.ValidatingAdmissionPolicy{}] = bindata.RecordingProfilesPolicyName
		byName[&admissionregv1.ValidatingAdmissionPolicyBinding{}] = bindata.RecordingProfilesPolicyName
	}

	for obj, name := range byName {
		opts.Cache.ByObject[obj] = cache.ByObject{
			Field: fields.OneTermEqualSelector("metadata.name", name),
		}
	}

	// The SPOD controller reads the operator ConfigMap on every
	// reconciliation and watches it.
	opts.Cache.ByObject[&corev1.ConfigMap{}] = cache.ByObject{
		Namespaces: map[string]cache.Config{operatorNamespace: {}},
		Field:      fields.OneTermEqualSelector("metadata.name", util.OperatorConfigMap),
	}

	opts.Cache.ByObject[&corev1.Pod{}] = cache.ByObject{Transform: stripPod}
}

// stripPod drops the fields of a cached pod which no manager controller
// reads, so that the cluster wide pod cache holds only the labels,
// annotations, UID, node name, images and security contexts of the pods.
// Other objects get the managed fields stripped by the default transform,
// which a per kind transform replaces.
func stripPod(obj any) (any, error) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}

	pod.ManagedFields = nil
	pod.Status = corev1.PodStatus{}
	pod.Spec.Volumes = nil

	for i := range pod.Spec.Containers {
		stripContainer(&pod.Spec.Containers[i])
	}

	for i := range pod.Spec.InitContainers {
		stripContainer(&pod.Spec.InitContainers[i])
	}

	for i := range pod.Spec.EphemeralContainers {
		ephemeral := &pod.Spec.EphemeralContainers[i]
		ctr := corev1.Container(ephemeral.EphemeralContainerCommon)
		stripContainer(&ctr)
		ephemeral.EphemeralContainerCommon = corev1.EphemeralContainerCommon(ctr)
	}

	return pod, nil
}

// stripContainer drops the container fields which no manager controller
// reads.
func stripContainer(ctr *corev1.Container) {
	ctr.Env = nil
	ctr.EnvFrom = nil
	ctr.Command = nil
	ctr.Args = nil
	ctr.VolumeMounts = nil
	ctr.VolumeDevices = nil
	ctr.Resources = corev1.ResourceRequirements{}
	ctr.LivenessProbe = nil
	ctr.ReadinessProbe = nil
	ctr.StartupProbe = nil
	ctr.Lifecycle = nil
	ctr.Ports = nil
}

func getEnabledControllers(ctx *cli.Context) []controller.Controller {
	controllers := []controller.Controller{}

	if ctx.Bool(seccompFlag) {
		controllers = append(controllers, seccompprofile.NewController())
	}

	if ctx.Bool(recordingFlag) {
		controllers = append(controllers, profilerecorder.NewController())
	}

	if ctx.Bool(selinuxFlag) {
		controllers = append(controllers, selinuxprofile.NewController())

		if ctx.Bool(rawSelinuxFlag) {
			controllers = append(controllers, selinuxprofile.NewRawController())
		}
	}

	if ctx.Bool(apparmorFlag) {
		controllers = append(controllers, apparmorprofile.NewController())
	}

	return controllers
}

// newDaemonCache creates the cache used by the daemon controllers.
//
// The daemon only ever acts on pods scheduled to its own node, so the pod cache
// is always restricted to those. Without that restriction every node would hold
// a copy of every pod in the cluster, which costs both memory per node and
// watch bandwidth on the API server.
//
// The same goes for the node statuses: the daemon only reads and writes the
// ones of its own node, while the cluster holds one per node and profile.
//
// When memory optimization is additionally enabled, only pods labeled for
// recording are cached on top of that.
func newDaemonCache(ctx *cli.Context) cache.NewCacheFunc {
	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		setupLog.Info(
			"Node name not set, caching pods and node statuses cluster wide",
			"env", config.NodeNameEnvKey,
		)
	}

	memOptim := ctx.Bool(memOptimFlag)

	return func(restConfig *rest.Config, opts cache.Options) (cache.Cache, error) {
		setDaemonCacheOptions(&opts, nodeName, memOptim)

		return cache.New(restConfig, opts)
	}
}

// setDaemonCacheOptions sets the cache options of the daemon, which restrict
// the pod cache to the pods of the node and, with memory optimization, to the
// pods labeled for recording. The node status cache is restricted to the
// statuses of the node by their node label, which every status carries since
// the per-node statuses got introduced.
func setDaemonCacheOptions(opts *cache.Options, nodeName string, memOptim bool) {
	byPod := cache.ByObject{}
	byObject := map[client.Object]cache.ByObject{}

	if nodeName != "" {
		byPod.Field = fields.OneTermEqualSelector("spec.nodeName", nodeName)
		byObject[&secprofnodestatusv1.SecurityProfileNodeStatus{}] = cache.ByObject{
			Label: labels.SelectorFromSet(labels.Set{
				secprofnodestatusv1.StatusToNodeLabel: util.NodeNameLabelValue(nodeName),
			}),
		}
	}

	if memOptim {
		byPod.Label = labels.SelectorFromSet(labels.Set{
			bindata.EnableRecordingLabel: "true",
		})
	}

	byObject[&corev1.Pod{}] = byPod

	opts.SyncPeriod = &daemonSyncPeriod
	opts.ByObject = byObject
}

// tlsConfig is the TLS configuration used by the controller-runtime servers
// (webhook and metrics) of a component.
type tlsConfig struct {
	// options are applied to the servers' *tls.Config.
	options []func(*tls.Config)

	// profile is the TLS profile the options were derived from.
	profile configv1.TLSProfileSpec

	// adherencePolicy says how strictly the cluster TLS profile is honored.
	adherencePolicy configv1.TLSAdherencePolicy

	// isOpenShift reports whether the cluster was detected as OpenShift.
	isOpenShift bool
}

// clusterConfig returns the config of the cluster connection and the initial
// TLS configuration of the servers, which the API server of OpenShift sets.
func clusterConfig(ctx context.Context) (*rest.Config, tlsConfig, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, tlsConfig{}, fmt.Errorf("get config: %w", err)
	}

	tlsCfg, err := fetchTLSOptions(ctx, cfg)
	if err != nil {
		return nil, tlsConfig{}, fmt.Errorf("fetch TLS options: %w", err)
	}

	return cfg, tlsCfg, nil
}

// fetchTLSOptions fetches the TLS configuration from the OpenShift APIServer
// and builds the TLS configuration for the controller-runtime servers. On
// non-OpenShift clusters it falls back to the Go defaults with a TLS 1.2
// minimum version.
func fetchTLSOptions(ctx context.Context, cfg *rest.Config) (tlsConfig, error) {
	setupLog.Info("detecting platform and fetching TLS configuration")

	// Create scheme and register OpenShift config API
	scheme := runtime.NewScheme()
	if err := configv1.AddToScheme(scheme); err != nil {
		return tlsConfig{}, fmt.Errorf("add OpenShift config API to scheme: %w", err)
	}

	// Create pre-start client to detect platform and fetch TLS configuration
	preStartClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return tlsConfig{}, fmt.Errorf("create pre-start client: %w", err)
	}

	return fetchClusterTLSOptions(ctx, preStartClient)
}

// fetchClusterTLSOptions detects the platform and fetches the TLS profile of
// the cluster with the provided client.
func fetchClusterTLSOptions(ctx context.Context, preStartClient client.Client) (tlsConfig, error) {
	var isOpenShift bool

	// Create a timeout context for OpenShift detection to avoid long waits on non-OpenShift clusters
	// Use 10 seconds to handle slow or loaded API servers during rolling restarts
	detectCtx, detectCancel := context.WithTimeout(ctx, 10*time.Second)
	defer detectCancel()

	// Detect if we're running on OpenShift using the same pattern as bindata/ca.go
	err := preStartClient.Get(detectCtx,
		types.NamespacedName{Name: "openshift-apiserver"},
		&configv1.ClusterOperator{},
	)

	switch {
	case err == nil:
		setupLog.Info("OpenShift detected, fetching cluster TLS configuration")

		isOpenShift = true
	case bindata.IsNotFound(err):
		setupLog.Info("OpenShift not detected, using default TLS configuration")

		isOpenShift = false
	default:
		return tlsConfig{}, fmt.Errorf("detect OpenShift platform: %w", err)
	}

	// Fetch TLS profile and adherence policy if on OpenShift
	var initialTLSProfile configv1.TLSProfileSpec

	var initialTLSAdherencePolicy configv1.TLSAdherencePolicy

	if isOpenShift {
		profileCtx, profileCancel := context.WithTimeout(ctx, 10*time.Second)
		defer profileCancel()

		initialTLSProfile, err = tlspkg.FetchAPIServerTLSProfile(profileCtx, preStartClient)
		if err != nil {
			// Fall back to default TLS profile if APIServer is temporarily unavailable
			// This prevents CrashLoopBackOff during API server restarts or upgrades
			setupLog.Info(
				"failed to fetch OpenShift TLS profile, falling back to default",
				"error", err,
			)

			initialTLSProfile, err = tlspkg.GetTLSProfileSpec(nil)
			if err != nil {
				return tlsConfig{}, fmt.Errorf("get default TLS profile: %w", err)
			}
		}

		adherenceCtx, adherenceCancel := context.WithTimeout(ctx, 10*time.Second)
		defer adherenceCancel()

		initialTLSAdherencePolicy, err = tlspkg.FetchAPIServerTLSAdherencePolicy(
			adherenceCtx, preStartClient,
		)
		if err != nil {
			// Fall back to NoOpinion if adherence policy fetch fails
			setupLog.Info(
				"failed to fetch OpenShift TLS adherence policy, falling back to NoOpinion",
				"error", err,
			)

			initialTLSAdherencePolicy = configv1.TLSAdherencePolicyNoOpinion
		}
	} else {
		// Use default TLS profile and adherence policy for non-OpenShift environments
		initialTLSProfile, err = tlspkg.GetTLSProfileSpec(nil)
		if err != nil {
			return tlsConfig{}, fmt.Errorf("get default TLS profile: %w", err)
		}

		initialTLSAdherencePolicy = configv1.TLSAdherencePolicyNoOpinion
	}

	return newTLSConfig(isOpenShift, initialTLSProfile, initialTLSAdherencePolicy), nil
}

// newTLSConfig builds the TLS configuration for the provided platform, TLS
// profile and adherence policy.
func newTLSConfig(
	isOpenShift bool,
	initialTLSProfile configv1.TLSProfileSpec,
	initialTLSAdherencePolicy configv1.TLSAdherencePolicy,
) tlsConfig {
	// Build TLS options - always disable HTTP/2
	tlsOptions := []func(config *tls.Config){
		func(c *tls.Config) {
			c.NextProtos = []string{"http/1.1"}
		},
	}

	// Apply TLS profile based on platform and adherence policy
	if isOpenShift {
		if libgocrypto.ShouldHonorClusterTLSProfile(initialTLSAdherencePolicy) {
			setupLog.Info(
				"honoring cluster TLS profile",
				"adherence-policy",
				initialTLSAdherencePolicy,
			)

			tlsConfigFunc, unsupportedCiphers := tlspkg.NewTLSConfigFromProfile(initialTLSProfile)
			if len(unsupportedCiphers) > 0 {
				setupLog.Info(
					"TLS profile contains unsupported ciphers",
					"ciphers",
					unsupportedCiphers,
				)
			}

			tlsOptions = append(tlsOptions, tlsConfigFunc)
		} else {
			setupLog.Info(
				"using default OpenShift TLS configuration",
				"adherence-policy",
				initialTLSAdherencePolicy,
			)
			// Apply OpenShift's default TLS profile when adherence policy does not require honoring cluster settings
			defaultProfile := configv1.TLSProfiles[libgocrypto.DefaultTLSProfileType]
			if defaultProfile != nil {
				defaultTLSConfig, unsupportedCiphers := tlspkg.NewTLSConfigFromProfile(
					*defaultProfile,
				)
				if len(unsupportedCiphers) > 0 {
					setupLog.Info(
						"default TLS configuration contains unsupported ciphers",
						"ciphers",
						unsupportedCiphers,
					)
				}

				tlsOptions = append(tlsOptions, defaultTLSConfig)
			}
		}
	} else {
		// On non-OpenShift clusters, use Go's built-in TLS defaults with minimum TLS 1.2
		// Don't apply OpenShift's cipher suite list to avoid breaking vanilla Kubernetes clients
		setupLog.Info("using Go default TLS configuration with TLS 1.2 minimum")

		tlsOptions = append(tlsOptions, func(c *tls.Config) {
			c.MinVersion = tls.VersionTLS12
		})
	}

	return tlsConfig{
		options:         tlsOptions,
		profile:         initialTLSProfile,
		adherencePolicy: initialTLSAdherencePolicy,
		isOpenShift:     isOpenShift,
	}
}

// secureMetricsOptions returns the metrics server options of the manager and
// the webhook. The metrics are served via TLS and require an authenticated and
// authorized client, like the ones of the daemon. No certificate is mounted
// for these components, so the server uses a self-signed one.
func secureMetricsOptions(tlsCfg *tlsConfig) metricsserver.Options {
	return metricsserver.Options{
		BindAddress:    fmt.Sprintf(":%d", metricsPort),
		SecureServing:  true,
		FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
		TLSOpts:        tlsCfg.options,
	}
}

// setupManagerWithTLSWatcher sets up TLS watching for a manager and starts it.
// The sigHandler parameter should be obtained from ctrl.SetupSignalHandler() in the caller.
func setupManagerWithTLSWatcher(
	sigHandler context.Context,
	mgr ctrl.Manager,
	tlsCfg *tlsConfig,
	componentName string,
) error {
	// Create a cancellable context derived from sigHandler for graceful shutdown on TLS config changes
	managerCtx, cancelManager := context.WithCancel(sigHandler)
	defer cancelManager()

	// Set up TLS profile watcher to trigger graceful shutdown on changes
	// This is only available in OpenShift environments
	var tlsConfigChanged atomic.Bool

	if tlsCfg.isOpenShift {
		if err := util.SetupTLSWatcher(mgr, tlsCfg.profile, tlsCfg.adherencePolicy,
			func(ctx context.Context, oldProfile, newProfile configv1.TLSProfileSpec) {
				tlsConfigChanged.Store(true)
				cancelManager()
			},
			func(ctx context.Context, oldPolicy, newPolicy configv1.TLSAdherencePolicy) {
				tlsConfigChanged.Store(true)
				cancelManager()
			}); err != nil {
			setupLog.Error(
				err,
				"TLS profile watcher setup failed, TLS configuration changes will not be detected",
			)
		} else {
			setupLog.Info(
				"TLS profile watcher enabled - will trigger graceful shutdown on configuration changes",
			)
		}
	} else {
		setupLog.Info("TLS profile watcher not enabled (OpenShift-only feature)")
	}

	setupLog.Info("starting " + componentName)

	if err := mgr.Start(managerCtx); err != nil {
		return fmt.Errorf("%s error: %w", componentName, err)
	}

	setupLog.Info("ending " + componentName)

	// If TLS config changed, return sentinel error so the pod restarts
	// This ensures a clean restart with new TLS settings
	if tlsConfigChanged.Load() {
		setupLog.Info(
			"exiting due to TLS configuration change - pod will restart with new settings",
		)

		return ErrTLSConfigChanged
	}

	return nil
}

func runDaemon(ctx *cli.Context, info *version.Info) error {
	// security-profiles-operator-daemon
	printInfo("spod", info)

	enabledControllers := getEnabledControllers(ctx)
	if len(enabledControllers) == 0 {
		return errors.New("no controllers enabled")
	}

	cfg, tlsCfg, err := clusterConfig(ctx.Context)
	if err != nil {
		return err
	}

	maxSeries := ctx.Int(maxMetricSeriesFlag)
	if maxSeries < 0 {
		return fmt.Errorf("%s must not be negative: %d", maxMetricSeriesFlag, maxSeries)
	}

	// Setup metrics
	met := metrics.New()
	met.SetMaxSeries(maxSeries)

	if err := met.Register(); err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}

	if err := met.ServeGRPC(); err != nil {
		return fmt.Errorf("start metrics grpc server: %w", err)
	}
	defer met.GracefulStop()

	operatorNamespace, err := config.TryToGetOperatorNamespace()
	if err != nil {
		return fmt.Errorf("get operator namespace: %w", err)
	}

	// The sync period of the cache is set by newDaemonCache.
	ctrlOpts := ctrl.Options{
		HealthProbeBindAddress: fmt.Sprintf(":%d", config.HealthProbePort),
		NewCache:               newDaemonCache(ctx),
		Metrics: metricsserver.Options{
			BindAddress:    fmt.Sprintf(":%d", bindata.ContainerPort),
			CertDir:        bindata.MetricsCertPath,
			SecureServing:  true,
			FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
			ExtraHandlers: map[string]http.Handler{
				metrics.HandlerPath: met.Handler(),
			},
			TLSOpts: tlsCfg.options,
		},
	}

	if ctx.Bool(insecureMetricsAccessFlag) {
		setupLog.Info("Insecure metrics access enabled, TLS and authentication are disabled")

		ctrlOpts.Metrics.SecureServing = false
		ctrlOpts.Metrics.CertDir = ""
		ctrlOpts.Metrics.FilterProvider = nil
		ctrlOpts.Metrics.TLSOpts = nil
	}

	setControllerOptionsForNamespaces(&ctrlOpts, operatorNamespace)

	// The node status API provides the status which every profile kind uses.
	// The manager uses the default scheme, which has to know the node status
	// kind of the cache options before the manager creates the cache.
	if err := addToScheme(clientgoscheme.Scheme,
		schemeAPI{"per-node Status v1", secprofnodestatusv1.AddToScheme},
		schemeAPI{"SPOD config v1", spodv1.AddToScheme},
	); err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := addCacheSyncReadyzCheck(mgr); err != nil {
		return err
	}

	if err := setupEnabledControllers(ctx.Context, enabledControllers, mgr, met); err != nil {
		return fmt.Errorf("enable controllers: %w", err)
	}

	sigHandler := ctrl.SetupSignalHandler()

	return setupManagerWithTLSWatcher(
		sigHandler,
		mgr,
		&tlsCfg,
		"daemon",
	)
}

func runBPFRecorder(_ *cli.Context, info *version.Info) error {
	const component = "bpf-recorder"

	printInfo(component, info)

	return bpfrecorder.New("", ctrl.Log.WithName(component), true, true).Run()
}

func runLogEnricher(ctx *cli.Context, info *version.Info) error {
	const component = "log-enricher"

	printInfo(component, info)

	opts := &enricher.LogEnricherOptions{
		EnricherFiltersJson: ctx.String(enricherFiltersJsonParam),
		AuditSource:         ctx.String(enricherLogSourceParam),
	}

	logEnricher, err := enricher.New(ctrl.Log.WithName(component), opts)
	if err != nil {
		return fmt.Errorf("create log enricher: %w", err)
	}

	return logEnricher.Run(ctrl.SetupSignalHandler())
}

func runJsonEnricher(ctx *cli.Context, info *version.Info) error {
	jsonEnricher, err := getJsonEnricher(ctx, info)
	if err != nil {
		return fmt.Errorf("could not create json enricher: %w", err)
	}

	sigCtx := ctrl.SetupSignalHandler()

	// Run returns once the signal context is done, after it emitted the
	// records which were still buffered and closed the audit log.
	runErr := make(chan error, 1)
	go jsonEnricher.Run(sigCtx, runErr)

	if err := <-runErr; err != nil {
		return fmt.Errorf("error while executing JSON Enricher: %w", err)
	}

	return nil
}

func getJsonEnricher(ctx *cli.Context, info *version.Info) (*enricher.JsonEnricher, error) {
	const component = "json-enricher"

	printInfo(component, info)

	opts := &enricher.JsonEnricherOptions{}

	if auditLogIntervalSeconds := ctx.Int(
		auditLogIntervalSecondsParam,
	); auditLogIntervalSeconds > 0 {
		opts.AuditFreq = time.Duration(auditLogIntervalSeconds) * time.Second
	}

	if auditLogPath := ctx.String(auditLogPathParam); auditLogPath != "" {
		opts.AuditLogPath = auditLogPath
	}

	opts.AuditLogMaxSize = ctx.Int(auditLogMaxSizeParam)
	opts.AuditLogMaxBackups = ctx.Int(auditLogMaxBackupParam)
	opts.AuditLogMaxAge = ctx.Int(auditLogMaxAgeParam)
	opts.EnricherFiltersJson = ctx.String(enricherFiltersJsonParam)

	setupLog.Info(
		"JSON Enricher Configuration",
		"AuditFreq", opts.AuditFreq,
		"AuditLogPath", opts.AuditLogPath,
		"AuditLogMaxSize", opts.AuditLogMaxSize,
		"AuditLogMaxBackup", opts.AuditLogMaxBackups,
		"AuditLogMaxAge", opts.AuditLogMaxAge,
		"EnricherFiltersJson", opts.EnricherFiltersJson,
	)

	jsonEnricher, err := enricher.NewJsonEnricherArgs(ctrl.Log.WithName(component),
		opts)
	if err != nil {
		return nil, err
	}

	return jsonEnricher, nil
}

func runNonRootEnabler(ctx *cli.Context, info *version.Info) error {
	const component = "non-root-enabler"

	printInfo(component, info)

	containerRuntime := ctx.String("runtime")
	apparmor := ctx.Bool("apparmor")

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	// A single read of the node needs no cache.
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	logger := ctrl.Log.WithName(component)

	kubeletDir, err := nonRootEnablerKubeletDir(
		ctx.Context, logger, c, os.Getenv(config.NodeNameEnvKey), config.DefaultKubeletDir(),
	)
	if err != nil {
		return err
	}

	return nonrootenabler.New().
		Run(logger, containerRuntime, kubeletDir, apparmor)
}

// nonRootEnablerKubeletDir returns the kubelet directory of the node from its
// label. The operator ignores the same missing or invalid labels, so the
// default kubelet directory defaultDir is the one mounted for such nodes. That
// default deliberately does not come from the kubelet configuration persisted on the
// node, which still holds the directory of a label that got removed. Failing
// to read the node is returned, so that the init container gets restarted
// rather than using the wrong directory.
func nonRootEnablerKubeletDir(
	ctx context.Context, logger logr.Logger, c client.Reader, nodeName, defaultDir string,
) (string, error) {
	kubeletDir, err := util.GetKubeletDirFromNodeLabel(ctx, c, nodeName)
	if err == nil {
		return kubeletDir, nil
	}

	if !errors.Is(err, util.ErrKubeletDirLabelNotFound) &&
		!errors.Is(err, util.ErrInvalidKubeletDirLabel) {
		return "", fmt.Errorf("getting the kubelet directory of the node: %w", err)
	}

	logger.Info("Using the default kubelet directory", "dir", defaultDir, "reason", err.Error())

	return defaultDir, nil
}

func runWebhook(ctx *cli.Context, info *version.Info) error {
	printInfo("security-profiles-operator-webhook", info)

	// Warn if deprecated tls-min-version flag is used
	if ctx.IsSet(tlsMinVersionParam) {
		setupLog.Info(
			"--tls-min-version flag is deprecated and ignored, " +
				"TLS configuration is now managed via OpenShift TLS profiles",
		)
	}

	cfg, tlsCfg, err := clusterConfig(ctx.Context)
	if err != nil {
		return err
	}

	port := ctx.Int("port")

	webhookServerOptions := webhook.Options{
		Port:    port,
		TLSOpts: tlsCfg.options,
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// The webhook is stateless and every replica serves requests, so no
	// leader election is required.
	ctrlOpts := manager.Options{
		Cache: cache.Options{
			DefaultTransform: cache.TransformStripManagedFields(),
		},
		HealthProbeBindAddress: fmt.Sprintf(":%d", config.HealthProbePort),
		WebhookServer:          webhookServer,
		Metrics:                secureMetricsOptions(&tlsCfg),
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create cluster manager: %w", err)
	}

	if err := addWebhookHealthChecks(mgr, webhookServer); err != nil {
		return err
	}

	// Register OpenShift config API for TLS watcher (watches APIServer resource for TLS profile changes)
	if err := addToScheme(mgr.GetScheme(),
		schemeAPI{"profilebinding v1", profilebindingv1.AddToScheme},
		schemeAPI{"seccompprofile v1", seccompprofilev1.AddToScheme},
		schemeAPI{"apparmorprofile v1", apparmorprofilev1.AddToScheme},
		schemeAPI{"selinuxprofile v1", selinuxprofilev1.AddToScheme},
		schemeAPI{"profilerecording v1", profilerecordingv1.AddToScheme},
		schemeAPI{"SPOD config v1", spodv1.AddToScheme},
	); err != nil {
		return err
	}

	setupLog.Info("registering webhooks")

	hookserver := mgr.GetWebhookServer()
	binding.RegisterWebhook(
		hookserver,
		mgr.GetScheme(),
		util.NewEventRecorder(mgr, "binding-webhook"),
		mgr.GetClient(),
		mgr.GetAPIReader(),
		tlsCfg.isOpenShift,
	)

	recording.RegisterWebhook(
		hookserver,
		mgr.GetScheme(),
		util.NewEventRecorder(mgr, "recording-webhook"),
		mgr.GetClient(),
	)
	execmetadata.RegisterWebhook(hookserver, mgr.GetAPIReader())
	validation.RegisterWebhook(hookserver, mgr.GetScheme())

	sigHandler := ctrl.SetupSignalHandler()

	return setupManagerWithTLSWatcher(
		sigHandler, mgr, &tlsCfg, "webhook",
	)
}

// schemeAPI is an API which a component registers with the scheme of its
// manager.
type schemeAPI struct {
	name string
	add  func(*runtime.Scheme) error
}

// addToScheme registers the OpenShift config API, which every component reads
// for the TLS profile, and the provided APIs with the scheme.
func addToScheme(scheme *runtime.Scheme, apis ...schemeAPI) error {
	for _, api := range append([]schemeAPI{{"OpenShift config", configv1.AddToScheme}}, apis...) {
		if err := api.add(scheme); err != nil {
			return fmt.Errorf("add %s API to scheme: %w", api.name, err)
		}
	}

	return nil
}

// readyzManager is the part of the manager which addCacheSyncReadyzCheck
// uses.
type readyzManager interface {
	AddReadyzCheck(name string, check healthz.Checker) error
	GetCache() cache.Cache
}

// addCacheSyncReadyzCheck marks the operator as not ready while the informer
// caches are not synced. `Manager.Start` serves the health endpoints before it
// waits for the caches, and that wait has no timeout, so a single informer which
// cannot list its resource (RBAC forbidding it, for example) keeps every
// controller from ever starting while the process still answers health checks.
// Without this check such an operator looks perfectly healthy while doing
// nothing at all.
func addCacheSyncReadyzCheck(mgr readyzManager) error {
	if err := mgr.AddReadyzCheck("cache-sync", func(req *http.Request) error {
		// Bound the check, because a cache which never syncs is the state to
		// report rather than to wait for.
		ctx, cancel := context.WithTimeout(req.Context(), cacheSyncCheckTimeout)
		defer cancel()

		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return errors.New("informer caches are not synced")
		}

		return nil
	}); err != nil {
		return fmt.Errorf("add cache sync readiness check: %w", err)
	}

	return nil
}

// addWebhookHealthChecks makes a webhook replica ready once its server
// accepts connections and its caches are synced, so that the service only
// sends admission requests to replicas which can answer them.
func addWebhookHealthChecks(mgr ctrl.Manager, server webhook.Server) error {
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("add webhook health check: %w", err)
	}

	if err := mgr.AddReadyzCheck("webhook", server.StartedChecker()); err != nil {
		return fmt.Errorf("add webhook readiness check: %w", err)
	}

	return addCacheSyncReadyzCheck(mgr)
}

func setupEnabledControllers(
	ctx context.Context,
	enabledControllers []controller.Controller,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	for _, enableCtrl := range enabledControllers {
		if sb := enableCtrl.SchemeBuilder(); sb != nil {
			if err := sb.AddToScheme(mgr.GetScheme()); err != nil {
				return fmt.Errorf("add core operator APIs to scheme: %w", err)
			}
		}

		if err := enableCtrl.Setup(ctx, mgr, met); err != nil {
			return fmt.Errorf("setup %s controller: %w", enableCtrl.Name(), err)
		}

		// Unconditionally, because controller-runtime only serves the liveness
		// endpoint at all once a check is registered, and the manager passes no
		// metrics while still exposing the health probe address.
		if err := mgr.AddHealthzCheck(enableCtrl.Name(), enableCtrl.Healthz); err != nil {
			return fmt.Errorf("add health check to controller: %w", err)
		}
	}

	return nil
}

// runCLI wraps the SPO CLI by using $PATH for searching the spoc executable.
// It passes the arguments after the command name, which do not depend on the
// global flags given before it.
func runCLI(ctx *cli.Context) error {
	return runSpoc(ctx.Args().Slice(), os.Stdin, os.Stdout, os.Stderr)
}

// runSpoc runs the spoc executable found in $PATH with the provided
// arguments. The exit code of spoc becomes the one of this process, so that
// scripts can tell a failed spoc invocation apart from a successful one.
func runSpoc(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	//nolint:gosec // it's intentional to pass all other args here
	c := exec.Command(spocCmd, args...)
	// For --password-stdin and the interactive OIDC sign-in.
	c.Stdin = stdin
	c.Stdout = stdout
	c.Stderr = stderr

	if err := c.Run(); err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return cli.Exit("", exitErr.ExitCode())
		}

		return fmt.Errorf("running %s: %w", spocCmd, err)
	}

	return nil
}
