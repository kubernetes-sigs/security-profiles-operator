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
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	selinuxpolicyv1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/profile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/selinuxpolicy"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	webhook "sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/binding"
)

const (
	jsonFlag               string = "json"
	selinuxFlag            string = "with-selinux"
	operatorImageKey       string = "RELATED_IMAGE_OPERATOR"
	nonRootEnablerImageKey string = "RELATED_IMAGE_NON_ROOT_ENABLER"
	selinuxdImageKey       string = "RELATED_IMAGE_SELINUXD"
	defaultPort            int    = 9443
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
			Usage:   "run the security-profiles-operator manager",
			Flags: []cli.Flag{
				&cli.IntFlag{
					Name:    "port",
					Aliases: []string{"p"},
					Value:   defaultPort,
					Usage:   "the port on which to expose the webhook service (default 9443)",
				},
			},
			Action: runManager,
		},
		&cli.Command{
			Name:    "daemon",
			Aliases: []string{"d"},
			Usage:   "run the security-profiles-operator daemon",
			Action:  runDaemon,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  selinuxFlag,
					Usage: "Listen for SELinux API resources",
					Value: false,
				},
			},
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

	port := ctx.Int("port")
	ctrlOpts := manager.Options{
		SyncPeriod:       &sync,
		LeaderElection:   true,
		LeaderElectionID: "security-profiles-operator-lock",
		Port:             port,
	}

	dt, err := getTunables()
	if err != nil {
		return err
	}

	if dt.WatchNamespace != "" {
		ctrlOpts.Namespace = dt.WatchNamespace
	}

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

	if err := spod.Setup(ctx.Context, mgr, &dt, ctrl.Log.WithName("spod-config")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	setupLog.Info("registering webhook")
	hookserver := mgr.GetWebhookServer()
	webhook.RegisterWebhook(hookserver, mgr.GetClient())

	setupLog.Info("starting manager")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	setupLog.Info("ending manager")
	return nil
}

func getTunables() (dt spod.DaemonTunables, err error) {
	dt.WatchNamespace = os.Getenv(config.RestrictNamespaceEnvKey)

	operatorImage := os.Getenv(operatorImageKey)
	if operatorImage == "" {
		return dt, errors.New("invalid operator image")
	}
	dt.DaemonImage = operatorImage

	nonRootEnableImage := os.Getenv(nonRootEnablerImageKey)
	if nonRootEnableImage == "" {
		return dt, errors.New("invalid non-root enabler image")
	}
	dt.NonRootEnablerImage = nonRootEnableImage

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

	enabledSettings = append(enabledSettings, &controllerSettings{
		name:          "seccomp-spod",
		setupFn:       profile.Setup,
		schemaBuilder: seccompprofilev1alpha1.SchemeBuilder,
	})

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
