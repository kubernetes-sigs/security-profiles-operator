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

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // required for profiling
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	configv1 "github.com/openshift/api/config/v1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsfilters "sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
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
	nodestatus "sigs.k8s.io/security-profiles-operator/internal/pkg/manager/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/recordingmerger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadannotator"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/execmetadata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording"
)

const (
	spocCmd                      string = "spoc"
	jsonFlag                     string = "json"
	nodeStatusControllerFlag     string = "with-nodestatus-controller"
	spodControllerFlag           string = "with-spod-controller"
	workloadAnnotatorFlag        string = "with-workload-annotator"
	recordingMergerFlag          string = "with-recording-merger"
	recordingFlag                string = "with-recording"
	seccompFlag                  string = "with-seccomp"
	selinuxFlag                  string = "with-selinux"
	apparmorFlag                 string = "with-apparmor"
	webhookFlag                  string = "webhook"
	memOptimFlag                 string = "with-mem-optim"
	defaultWebhookPort           int    = 9443
	auditLogIntervalSecondsParam string = "audit-log-interval-seconds"
	auditLogPathParam            string = "audit-log-path"
	auditLogMaxSizeParam         string = "audit-log-maxsize"
	// The plural form is not used for audit-log-file-maxbackup to match the k8s api server audit log options.
	auditLogMaxBackupParam   string = "audit-log-maxbackup"
	auditLogMaxAgeParam      string = "audit-log-maxage"
	enricherFiltersJsonParam string = "enricher-filters-json"
	enricherLogSourceParam   string = "enricher-log-source"
	tlsMinVersionParam       string = "tls-min-version"
	defaultTlsMinVersion     string = "1.2"
)

var (
	sync             = time.Second * 30
	setupLog         = ctrl.Log.WithName("setup")
	tlsMinVersionMap = map[string]uint16{
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
)

func main() {
	// This is required to close any open resource like a file
	mainctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		// No logger may be available hence using fmt
		fmt.Printf("\nReceived OS signal: %s. Initiating graceful shutdown...\n", sig)
		cancel()
	}()

	app, info := cmd.DefaultApp()
	app.Name = config.OperatorName
	app.Usage = "Kubernetes Security Profiles Operator"
	app.Description = "The Security Profiles Operator makes it easier for cluster admins " +
		"to manage their seccomp or AppArmor profiles and apply them to Kubernetes' workloads."

	app.Commands = append(app.Commands,
		&cli.Command{
			Before:  initialize,
			Name:    "manager",
			Aliases: []string{"m"},
			Usage:   "run the manager",
			Action: func(ctx *cli.Context) error {
				return runManager(ctx, info)
			},
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    webhookFlag,
					Aliases: []string{"w"},
					Value:   true,
					Usage:   "the webhook k8s resources are managed by the operator(default true)",
				},
				&cli.BoolFlag{
					Name:  nodeStatusControllerFlag,
					Value: true,
					Usage: "Enable the node status controller.",
				},
				&cli.BoolFlag{
					Name:  spodControllerFlag,
					Value: true,
					Usage: "Enable the SPOD controller.",
				},
				&cli.BoolFlag{
					Name:  workloadAnnotatorFlag,
					Value: true,
					Usage: "Enable the workload annotator.",
				},
				&cli.BoolFlag{
					Name:  recordingMergerFlag,
					Value: true,
					Usage: "Enable the recording merger.",
				},
			},
		},
		&cli.Command{
			Before:  initialize,
			Name:    "daemon",
			Aliases: []string{"d"},
			Usage:   "run the daemon",
			Action: func(ctx *cli.Context) error {
				return runDaemon(ctx, info)
			},
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  seccompFlag,
					Usage: "Listen for seccomp API resources",
					Value: true,
				},
				&cli.BoolFlag{
					Name:  selinuxFlag,
					Usage: "Listen for SELinux API resources",
					Value: false,
				},
				&cli.BoolFlag{
					Name:  apparmorFlag,
					Usage: "Listen for AppArmor API resources",
					Value: false,
				},
				&cli.BoolFlag{
					Name:    recordingFlag,
					Usage:   "Listen for ProfileRecording API resources",
					Value:   false,
					EnvVars: []string{config.EnableRecordingEnvKey},
				},
				&cli.BoolFlag{
					Name:  memOptimFlag,
					Usage: "Enable memory optimization by watching only labeled pods",
					Value: false,
				},
			},
		},
		&cli.Command{
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
					Usage:   "the port on which to expose the webhook service (default 9443)",
				},
				&cli.BoolFlag{
					Name:    "static",
					Aliases: []string{"s"},
					Value:   false,
					Usage:   "the webhook k8s resources are statically managed (default false)",
				},
				&cli.GenericFlag{
					Name:  tlsMinVersionParam,
					Value: util.NewEnumValue([]string{"1.2", "1.3"}, "1.2"),
					Usage: "minimum TLS version to use for the SPO webhooks. Supported values: 1.2, 1.3. (default: 1.2)",
				},
			},
		},
		&cli.Command{
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
					Usage:   "the container runtime in the cluster (values: cri-o, containerd, docker)",
				},
				&cli.BoolFlag{
					Name:    "apparmor",
					Aliases: []string{"a"},
					Usage:   "enable installation of apparmor profiles for spo",
					EnvVars: []string{config.AppArmorEnvKey},
				},
			},
		},
		&cli.Command{
			Before:  initialize,
			Name:    "log-enricher",
			Aliases: []string{"l"},
			Usage:   "run the audit's log enricher",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:  enricherFiltersJsonParam,
					Value: "",
					Usage: "Log Enricher filters JSON.",
				},
				&cli.StringFlag{
					Name:  enricherLogSourceParam,
					Value: "",
					Usage: "Log source to ingest (`bpf` or `auditd`)",
				},
			},
			Action: func(ctx *cli.Context) error {
				return runLogEnricher(ctx, info)
			},
		},
		&cli.Command{
			Before:  initialize,
			Name:    "json-enricher",
			Aliases: []string{"j"},
			Usage:   "run the audit's json enricher",
			Action: func(ctx *cli.Context) error {
				jsonEnricher, err := getJsonEnricher(ctx, info)
				if err != nil {
					return fmt.Errorf("could not create json enricher: %w", err)
				}

				runErr := make(chan error)
				go jsonEnricher.Run(mainctx, runErr)

				select {
				case <-runErr:
					return fmt.Errorf("error while executing JSON Enricher: %w", <-runErr)
				case <-mainctx.Done():
					// Cannot use CLI "After" as exit signal won't invoke it
					fmt.Printf("Exit JSON Enricher")
					jsonEnricher.ExitJsonEnricher(ctx)

					return nil
				}
			},
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:    auditLogIntervalSecondsParam,
					Aliases: []string{"a"},
					Value:   60,
					Usage:   "Audit log interval in seconds for the JSON Log Enricher.",
				},
				&cli.StringFlag{
					Name:  auditLogPathParam,
					Value: "",
					Usage: "Audit log file path for the JSON Log Enricher. Default is stdout.",
				},
				&cli.IntFlag{
					Name:  auditLogMaxBackupParam,
					Value: 0,
					Usage: "Audit log max file backup for the JSON Log Enricher. " +
						"The maximum number of old audit log files to retain. " +
						"Setting a value of 0 will mean there's no restriction on the number of files.",
				},
				&cli.IntFlag{
					Name:  auditLogMaxSizeParam,
					Value: 100,
					Usage: "Audit log max file size for the JSON Log Enricher. " +
						"The maximum size in megabytes of the audit log file before it gets rotated.",
				},
				&cli.IntFlag{
					Name:  auditLogMaxAgeParam,
					Value: 0,
					Usage: "Audit log max age for the JSON Log Enricher. " +
						"The maximum number of days to retain old audit log files based " +
						"on the timestamp encoded in their filename.",
				},
				&cli.StringFlag{
					Name:  enricherFiltersJsonParam,
					Value: "",
					Usage: "JSON Enricher filters JSON file path.",
				},
			},
		},
		&cli.Command{
			Before:  initialize,
			Name:    "bpf-recorder",
			Aliases: []string{"b"},
			Usage:   "run the bpf recorder",
			Action: func(ctx *cli.Context) error {
				return runBPFRecorder(ctx, info)
			},
		},
		&cli.Command{
			Name:     spocCmd,
			Aliases:  []string{"s"},
			Usage:    "run the CLI",
			Action:   runCLI,
			HideHelp: true,
		},
	)

	app.Flags = []cli.Flag{
		&cli.UintFlag{
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
	}

	if err := app.Run(os.Args); err != nil {
		setupLog.Error(err, "running security-profiles-operator")
		//nolint:gocritic // this is intentional to return to correct exit code
		os.Exit(1)
	}

	if err := app.RunContext(mainctx, os.Args); err != nil {
		fmt.Printf("application error: %v", err)
	}
}

func initialize(ctx *cli.Context) error {
	if err := initLogging(ctx); err != nil {
		return fmt.Errorf("init logging: %w", err)
	}

	initProfiling(ctx)

	return nil
}

func initLogging(ctx *cli.Context) error {
	logConfig := textlogger.NewConfig()
	ctrl.SetLogger(textlogger.NewLogger(logConfig))

	set := flag.NewFlagSet("logging", flag.ContinueOnError)
	klog.InitFlags(set)

	level := ctx.Uint("verbosity")
	if err := set.Parse([]string{fmt.Sprintf("-v=%d", level)}); err != nil {
		return fmt.Errorf("parse verbosity flag: %w", err)
	}

	ctrl.SetLogger(ctrl.Log.V(int(level)))

	if err := logConfig.Verbosity().Set(strconv.FormatUint(uint64(level), 10)); err != nil {
		return fmt.Errorf("setting the verbosity flag to level %d: %w", level, err)
	}

	ctrl.Log.Info(fmt.Sprintf("Set logging verbosity to %d", level))

	return nil
}

func initProfiling(ctx *cli.Context) {
	enabled := ctx.Bool("profiling")
	ctrl.Log.Info(fmt.Sprintf("Profiling support enabled: %v", enabled))

	if enabled {
		go func() {
			port := ctx.Uint("profiling-port")
			endpoint := fmt.Sprintf(":%d", port)

			ctrl.Log.Info("Starting profiling server", "endpoint", endpoint)

			server := &http.Server{
				Addr:              endpoint,
				ReadHeaderTimeout: util.DefaultReadHeaderTimeout,
			}
			if err := server.ListenAndServe(); err != nil {
				ctrl.Log.Error(err, "unable to run profiling server")
			}
		}()
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

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	sigHandler := ctrl.SetupSignalHandler()

	ctrlOpts := manager.Options{
		Cache:            cache.Options{SyncPeriod: &sync},
		LeaderElection:   true,
		LeaderElectionID: "security-profiles-operator-lock",
	}

	setControllerOptionsForNamespaces(&ctrlOpts)

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create cluster manager: %w", err)
	}

	if err := configv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add OpenShift config API to scheme: %w", err)
	}

	if err := certmanagerv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add certmanager API to scheme: %w", err)
	}

	if err := profilebindingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add profilebinding API to scheme: %w", err)
	}

	if err := seccompprofileapi.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add seccompprofile API to scheme: %w", err)
	}

	if err := apparmorprofileapi.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add apparmorprofile API to scheme: %w", err)
	}

	if err := selxv1alpha2.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add selinuxprofile API to scheme: %w", err)
	}

	if err := monitoringv1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add ServiceMonitor API to scheme: %w", err)
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

	setupLog.Info("enabled controllers", "controllers", enabledControllers)

	if err := setupEnabledControllers(
		context.WithValue(ctx.Context, spod.ManageWebhookKey, manageWebhook(ctx)),
		enabledControllers, mgr, nil); err != nil {
		return fmt.Errorf("enable controllers: %w", err)
	}

	setupLog.Info("starting manager")

	if err := mgr.Start(sigHandler); err != nil {
		return fmt.Errorf("controller manager error: %w", err)
	}

	setupLog.Info("ending manager")

	return nil
}

func setControllerOptionsForNamespaces(opts *ctrl.Options) {
	namespace, ok := os.LookupEnv(config.RestrictNamespaceEnvKey)
	if !ok {
		namespace = os.Getenv("WATCH_NAMESPACE")
	}

	// listen globally
	if namespace == "" {
		setupLog.Info("watching all namespaces")

		return
	}

	// ensure we listen to our own namespace
	if !strings.Contains(namespace, config.GetOperatorNamespace()) {
		namespace = namespace + "," + config.GetOperatorNamespace()
	}

	namespaceList := strings.Split(namespace, ",")
	// Add support for MultiNamespace set in WATCH_NAMESPACE (e.g ns1,ns2)
	// Note that this is not intended to be used for excluding namespaces, this is better done via a Predicate
	// Also note that you may face performance issues when using this with a high number of namespaces.
	// More Info: https://godoc.org/github.com/kubernetes-sigs/controller-runtime/pkg/cache#MultiNamespacedCacheBuilder
	// Adding "" adds cluster namespaced resources
	if strings.Contains(namespace, ",") {
		opts.Cache.DefaultNamespaces = make(map[string]cache.Config, len(namespaceList))
		for _, ns := range namespaceList {
			opts.Cache.DefaultNamespaces[ns] = cache.Config{}
		}

		setupLog.Info("watching multiple namespaces", "namespaces", namespaceList)
	} else {
		// listen to a specific namespace only
		opts.Cache.DefaultNamespaces = map[string]cache.Config{namespace: {}}
		setupLog.Info("watching single namespace", "namespace", namespace)
	}
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
		controllers = append(controllers,
			selinuxprofile.NewController(),
			selinuxprofile.NewRawController())
	}

	if ctx.Bool(apparmorFlag) {
		controllers = append(controllers, apparmorprofile.NewController())
	}

	return controllers
}

// newMemoryOptimizedCache creates a memory optimized cache for daemon controller.
// This will load into cache memory only the pods objects which are labeled for recording.
func newMemoryOptimizedCache(ctx *cli.Context) cache.NewCacheFunc {
	if ctx.Bool(memOptimFlag) {
		return func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			opts.SyncPeriod = &sync
			opts.ByObject = map[client.Object]cache.ByObject{
				&corev1.Pod{}: {
					Label: labels.SelectorFromSet(labels.Set{
						bindata.EnableRecordingLabel: "true",
					}),
				},
			}
			opts.DefaultLabelSelector = labels.Everything()

			return cache.New(config, opts)
		}
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

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	sigHandler := ctrl.SetupSignalHandler()

	// Setup metrics
	met := metrics.New()
	if err := met.Register(); err != nil {
		return fmt.Errorf("register metrics: %w", err)
	}

	if err := met.ServeGRPC(); err != nil {
		return fmt.Errorf("start metrics grpc server: %w", err)
	}

	ctrlOpts := ctrl.Options{
		Cache:                  cache.Options{SyncPeriod: &sync},
		HealthProbeBindAddress: fmt.Sprintf(":%d", config.HealthProbePort),
		NewCache:               newMemoryOptimizedCache(ctx),
		Metrics: metricsserver.Options{
			BindAddress:    fmt.Sprintf(":%d", bindata.ContainerPort),
			CertDir:        bindata.MetricsCertPath,
			SecureServing:  true,
			FilterProvider: metricsfilters.WithAuthenticationAndAuthorization,
			ExtraHandlers: map[string]http.Handler{
				metrics.HandlerPath: met.Handler(),
			},
		},
	}

	setControllerOptionsForNamespaces(&ctrlOpts)

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	// This API provides status which is used by both seccomp and selinux
	if err := secprofnodestatusv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add per-node Status API to scheme: %w", err)
	}

	if err := spodv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add SPOD config API to scheme: %w", err)
	}

	if err := setupEnabledControllers(ctx.Context, enabledControllers, mgr, met); err != nil {
		return fmt.Errorf("enable controllers: %w", err)
	}

	setupLog.Info("starting daemon")

	if err := mgr.Start(sigHandler); err != nil {
		return fmt.Errorf("SPOd error: %w", err)
	}

	setupLog.Info("ending daemon")

	return nil
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

	return logEnricher.Run()
}

func getJsonEnricher(ctx *cli.Context, info *version.Info) (*enricher.JsonEnricher, error) {
	const component = "json-enricher"

	printInfo(component, info)

	opts := &enricher.JsonEnricherOptions{}

	if auditLogIntervalSeconds := ctx.Int(auditLogIntervalSecondsParam); auditLogIntervalSeconds > 0 {
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

	runtime := ctx.String("runtime")
	apparmor := ctx.Bool("apparmor")

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{})
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	kubeletDir, err := util.GetKubeletDirFromNodeLabel(ctx.Context, mgr.GetAPIReader())
	if err != nil {
		kubeletDir = config.KubeletDir()
	}

	return nonrootenabler.New().Run(ctrl.Log.WithName(component), runtime, kubeletDir, apparmor)
}

func runWebhook(ctx *cli.Context, info *version.Info) error {
	printInfo("security-profiles-operator-webhook", info)

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get config: %w", err)
	}

	port := ctx.Int("port")

	var tlsMinVersionStr string

	tlsMinVersion, ok := ctx.Generic(tlsMinVersionParam).(util.EnumValue)
	if !ok {
		tlsMinVersionStr = defaultTlsMinVersion
	} else {
		tlsMinVersionStr = tlsMinVersion.String()
	}

	tlsConfig := func(c *tls.Config) {
		c.NextProtos = []string{"http/1.1"}
		c.MinVersion = tlsMinVersionMap[tlsMinVersionStr]
	}

	webhookServerOptions := webhook.Options{
		Port:    port,
		TLSOpts: []func(config *tls.Config){tlsConfig},
	}

	webhookServer := webhook.NewServer(webhookServerOptions)
	ctrlOpts := manager.Options{
		Cache:            cache.Options{SyncPeriod: &sync},
		LeaderElection:   true,
		LeaderElectionID: "security-profiles-operator-webhook-lock",
		WebhookServer:    webhookServer,
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return fmt.Errorf("create cluster webhook: %w", err)
	}

	if err := profilebindingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add profilebinding API to scheme: %w", err)
	}

	if err := seccompprofileapi.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add seccompprofile API to scheme: %w", err)
	}

	if err := apparmorprofileapi.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add apparmorprofile API to scheme: %w", err)
	}

	if err := selxv1alpha2.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add selinuxprofile API to scheme: %w", err)
	}

	if err := profilerecording1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return fmt.Errorf("add profilerecording API to scheme: %w", err)
	}

	setupLog.Info("registering webhooks")

	hookserver := mgr.GetWebhookServer()
	binding.RegisterWebhook(hookserver, mgr.GetScheme(), mgr.GetClient())
	recording.RegisterWebhook(hookserver, mgr.GetScheme(), mgr.GetEventRecorderFor("recording-webhook"), mgr.GetClient())
	execmetadata.RegisterWebhook(hookserver)

	sigHandler := ctrl.SetupSignalHandler()

	setupLog.Info("starting webhook")

	if err := mgr.Start(sigHandler); err != nil {
		return fmt.Errorf("controller manager error: %w", err)
	}

	return nil
}

func setupEnabledControllers(
	ctx context.Context,
	enabledControllers []controller.Controller,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	for _, enableCtrl := range enabledControllers {
		if enableCtrl.SchemeBuilder() != nil {
			if err := enableCtrl.SchemeBuilder().AddToScheme(mgr.GetScheme()); err != nil {
				return fmt.Errorf("add core operator APIs to scheme: %w", err)
			}
		}

		if err := enableCtrl.Setup(ctx, mgr, met); err != nil {
			return fmt.Errorf("setup %s controller: %w", enableCtrl.Name(), err)
		}

		if met != nil {
			if err := mgr.AddHealthzCheck(enableCtrl.Name(), enableCtrl.Healthz); err != nil {
				return fmt.Errorf("add readiness check to controller: %w", err)
			}
		}
	}

	return nil
}

// runCLI wraps the SPO CLI by using $PATH for searching the spoc executable.
func runCLI(_ *cli.Context) error {
	const minArgs = 2
	if len(os.Args) < minArgs {
		return errors.New("not enough arguments provided")
	}
	//nolint:gosec // it's intentional to pass all other args here
	c := exec.Command(spocCmd, os.Args[minArgs:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	return nil
}
