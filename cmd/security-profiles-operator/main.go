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
	"time"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	profilebindingv1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	selinuxpolicyv1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/seccompprofile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/selinuxpolicy"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording"
)

const (
	jsonFlag           string = "json"
	selinuxFlag        string = "with-selinux"
	selinuxdImageKey   string = "RELATED_IMAGE_SELINUXD"
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
			Name:  "non-root-enabler",
			Usage: "run the non root enabler",
			Action: func(*cli.Context) error {
				return nonrootenabler.New().Run()
			},
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

	dt, err := getTunables()
	if err != nil {
		return err
	}

	// Given that the operator manager only deploys the SPOd and currently
	// doesn't hold any webhooks, we only listen on the operator's
	// namespace.
	ctrlOpts.Namespace = config.GetOperatorNamespace()

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create cluster manager")
	}

	if err := spodv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add SPOD API to scheme")
	}
	if err := profilebindingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add profilebinding API to scheme")
	}
	if err := seccompprofilev1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add seccompprofile API to scheme")
	}

	if err := spod.Setup(ctx.Context, mgr, &dt, ctrl.Log.WithName("spod-config")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	setupLog.Info("ending manager")
	return nil
}

func getTunables() (dt spod.DaemonTunables, err error) {
	dt.WatchNamespace = os.Getenv(config.RestrictNamespaceEnvKey)

	selinuxdImage := os.Getenv(selinuxdImageKey)
	if selinuxdImage == "" {
		return dt, errors.New("invalid selinuxd image")
	}
	dt.SelinuxdImage = selinuxdImage

	return dt, nil
}

// TODO(jhrozek): the type seems out of place here, maybe we should move it to a file under internal/pkg/controllers
// that would just define the type and nothing else.
type daemonSetupFunc func(ctx context.Context, mgr ctrl.Manager, l logr.Logger) error

type controllerSettings struct {
	name          string
	setupFn       daemonSetupFunc
	schemaBuilder *scheme.Builder
}

func getEnabledControllers(ctx *cli.Context) []*controllerSettings {
	enabledSettings := make([]*controllerSettings, 0, 2)

	enabledSettings = append(enabledSettings,
		&controllerSettings{
			name:          "seccomp-spod",
			setupFn:       seccompprofile.Setup,
			schemaBuilder: seccompprofilev1alpha1.SchemeBuilder,
		},
		&controllerSettings{
			name:          "recorder-spod",
			setupFn:       profilerecorder.Setup,
			schemaBuilder: seccompprofilev1alpha1.SchemeBuilder,
		},
	)

	if ctx.Bool(selinuxFlag) {
		enabledSettings = append(enabledSettings, &controllerSettings{
			name:          "selinux-spod",
			setupFn:       selinuxpolicy.Setup,
			schemaBuilder: selinuxpolicyv1alpha1.SchemeBuilder,
		})
	}

	return enabledSettings
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
		SyncPeriod: &sync,
	}

	if os.Getenv(config.RestrictNamespaceEnvKey) != "" {
		ctrlOpts.Namespace = os.Getenv(config.RestrictNamespaceEnvKey)
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create manager")
	}

	err = setupEnabledControllers(ctx.Context, enabledControllers, mgr)
	if err != nil {
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
	printInfo("log-enricher")
	enricher.Run(ctrl.Log.WithName("log-enricher"))
	return nil
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

func setupEnabledControllers(ctx context.Context, enabledControllers []*controllerSettings, mgr ctrl.Manager) error {
	for _, enableCtrl := range enabledControllers {
		if err := enableCtrl.schemaBuilder.AddToScheme(mgr.GetScheme()); err != nil {
			return errors.Wrap(err, "add core operator APIs to scheme")
		}

		if err := enableCtrl.setupFn(ctx, mgr, ctrl.Log.WithName(enableCtrl.name)); err != nil {
			return errors.Wrapf(err, "setup %s controller", enableCtrl.name)
		}
	}

	return nil
}
