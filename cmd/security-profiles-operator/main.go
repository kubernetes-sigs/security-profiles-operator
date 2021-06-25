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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/urfave/cli/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	selinuxprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/selinuxprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/server"
	nodestatus "sigs.k8s.io/security-profiles-operator/internal/pkg/manager/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/workloadannotator"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording"
)

const (
	jsonFlag           string = "json"
	selinuxFlag        string = "with-selinux"
	defaultWebhookPort int    = 9443
)

var (
	sync     = time.Second * 30
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	ctrl.SetLogger(klogr.New())

	app := cli.NewApp()
	app.Name = config.OperatorName
	app.Usage = "Kubernetes Security Profiles Operator"
	app.Description = "The Security Profiles Operator makes it easier for cluster admins " +
		"to manage their seccomp or AppArmor profiles and apply them to Kubernetes' workloads."
	app.Version = version.Get().Version
	app.Commands = cli.Commands{
		&cli.Command{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "display detailed version information",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    jsonFlag,
					Aliases: []string{"j"},
					Usage:   "print JSON instead of text",
				},
			},
			Action: func(c *cli.Context) error {
				v := version.Get()
				res := v.String()
				if c.Bool(jsonFlag) {
					j, err := v.JSONString()
					if err != nil {
						return errors.Wrap(err, "unable to generate JSON from version info")
					}
					res = j
				}
				print(res)
				return nil
			},
		},
		&cli.Command{
			Name:    "manager",
			Aliases: []string{"m"},
			Usage:   "run the manager",
			Action:  runManager,
		},
		&cli.Command{
			Name:    "daemon",
			Aliases: []string{"d"},
			Usage:   "run the daemon",
			Action:  runDaemon,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  selinuxFlag,
					Usage: "Listen for SELinux API resources",
					Value: false,
				},
			},
		},
		&cli.Command{
			Name:    "webhook",
			Aliases: []string{"w"},
			Usage:   "run the webhook",
			Action:  runWebhook,
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:    "port",
					Aliases: []string{"p"},
					Value:   defaultWebhookPort,
					Usage:   "the port on which to expose the webhook service (default 9443)",
				},
			},
		},
		&cli.Command{
			Name:   "non-root-enabler",
			Usage:  "run the non root enabler",
			Action: runNonRootEnabler,
		},
		&cli.Command{
			Name:    "log-enricher",
			Aliases: []string{"l"},
			Usage:   "run the audit's log enricher",
			Action:  runLogEnricher,
		},
	}

	if err := app.Run(os.Args); err != nil {
		setupLog.Error(err, "running security-profiles-operator")
		os.Exit(1)
	}
}

func printInfo(component string) {
	v := version.Get()
	setupLog.Info(
		fmt.Sprintf("starting component: %s", component),
		"version", v.Version,
		"gitCommit", v.GitCommit,
		"gitTreeState", v.GitTreeState,
		"buildDate", v.BuildDate,
		"goVersion", v.GoVersion,
		"compiler", v.Compiler,
		"platform", v.Platform,
	)
}

func runManager(ctx *cli.Context) error {
	printInfo("security-profiles-operator")
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "get config")
	}

	sigHandler := ctrl.SetupSignalHandler()

	ctrlOpts := manager.Options{
		SyncPeriod:       &sync,
		LeaderElection:   true,
		LeaderElectionID: "security-profiles-operator-lock",
	}

	setControllerOptionsForNamespaces(&ctrlOpts)

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create cluster manager")
	}

	if err := profilebindingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add profilebinding API to scheme")
	}
	if err := seccompprofilev1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add seccompprofile API to scheme")
	}
	if err := selinuxprofilev1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add selinuxprofile API to scheme")
	}
	if err := monitoringv1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add ServiceMonitor API to scheme")
	}

	if err := setupEnabledControllers(ctx.Context, []controller.Controller{
		nodestatus.NewController(),
		spod.NewController(),
		workloadannotator.NewController(),
	}, mgr, nil); err != nil {
		return errors.Wrap(err, "enable controllers")
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	setupLog.Info("ending manager")
	return nil
}

func setControllerOptionsForNamespaces(opts *ctrl.Options) {
	namespace := os.Getenv(config.RestrictNamespaceEnvKey)

	// listen globally
	if namespace == "" {
		opts.Namespace = namespace
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
		opts.NewCache = cache.MultiNamespacedCacheBuilder(namespaceList)
	} else {
		// listen to a specific namespace only
		opts.Namespace = namespace
	}
}

func getEnabledControllers(ctx *cli.Context) []controller.Controller {
	controllers := make([]controller.Controller, 0, 2)

	controllers = append(controllers,
		seccompprofile.NewController(),
		profilerecorder.NewController(),
	)

	if ctx.Bool(selinuxFlag) {
		controllers = append(controllers, selinuxprofile.NewController())
	}

	return controllers
}

func runDaemon(ctx *cli.Context) error {
	// security-profiles-operator-daemon
	printInfo("spod")

	enabledControllers := getEnabledControllers(ctx)
	if len(enabledControllers) == 0 {
		return errors.New("no controllers enabled")
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "get config")
	}

	sigHandler := ctrl.SetupSignalHandler()

	ctrlOpts := ctrl.Options{
		SyncPeriod:             &sync,
		HealthProbeBindAddress: fmt.Sprintf(":%d", config.HealthProbePort),
	}

	setControllerOptionsForNamespaces(&ctrlOpts)

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create manager")
	}

	// Setup metrics
	met := metrics.New()
	if err := met.Register(); err != nil {
		return errors.Wrap(err, "register metrics")
	}

	if err := mgr.AddMetricsExtraHandler(metrics.HandlerPath, met.Handler()); err != nil {
		return errors.Wrap(err, "add metrics extra handler")
	}

	// Setup the GRPC server
	if err := server.New(ctrl.Log.WithName("server"), met).Start(); err != nil {
		return errors.Wrap(err, "start GRPC server")
	}

	// This API provides status which is used by both seccomp and selinux
	if err := secprofnodestatusv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add per-node Status API to scheme")
	}

	if err := setupEnabledControllers(ctx.Context, enabledControllers, mgr, met); err != nil {
		return errors.Wrap(err, "enable controllers")
	}

	setupLog.Info("starting daemon")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "SPOd error")
	}

	setupLog.Info("ending daemon")
	return nil
}

func runLogEnricher(ctx *cli.Context) error {
	const component = "log-enricher"
	printInfo(component)
	return enricher.New(ctrl.Log.WithName(component)).Run()
}

func runNonRootEnabler(ctx *cli.Context) error {
	const component = "non-root-enabler"
	printInfo(component)
	return nonrootenabler.New().Run(ctrl.Log.WithName(component))
}

func runWebhook(ctx *cli.Context) error {
	printInfo("security-profiles-operator-webhook")
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "get config")
	}

	port := ctx.Int("port")
	ctrlOpts := manager.Options{
		SyncPeriod:       &sync,
		LeaderElection:   true,
		LeaderElectionID: "security-profiles-operator-webhook-lock",
		Port:             port,
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create cluster webhook")
	}

	if err := profilebindingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add profilebinding API to scheme")
	}
	if err := seccompprofilev1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add seccompprofile API to scheme")
	}
	if err := profilerecording1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add profilerecording API to scheme")
	}

	setupLog.Info("registering webhooks")
	hookserver := mgr.GetWebhookServer()
	binding.RegisterWebhook(hookserver, mgr.GetClient())
	recording.RegisterWebhook(hookserver, mgr.GetClient())

	sigHandler := ctrl.SetupSignalHandler()
	setupLog.Info("starting webhook")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "controller manager error")
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
				return errors.Wrap(err, "add core operator APIs to scheme")
			}
		}

		if err := enableCtrl.Setup(ctx, mgr, met); err != nil {
			return errors.Wrapf(err, "setup %s controller", enableCtrl.Name())
		}

		if met != nil {
			if err := mgr.AddHealthzCheck(enableCtrl.Name(), enableCtrl.Healthz); err != nil {
				return errors.Wrap(err, "add readiness check to controller")
			}
		}
	}

	return nil
}
