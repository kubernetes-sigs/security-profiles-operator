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
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"k8s.io/klog/v2/klogr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	selinuxpolicyv1alpha1 "sigs.k8s.io/security-profiles-operator/api/selinuxpolicy/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/profile"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/selinuxpolicy"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controllers/spod"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
	slns "sigs.k8s.io/security-profiles-operator/internal/pkg/webhook/namespace"
)

const (
	jsonFlag               string = "json"
	enableWebhookFlag      string = "enable-webhook"
	restrictNSKey          string = "RESTRICT_TO_NAMESPACE"
	operatorImageKey       string = "RELATED_IMAGE_OPERATOR"
	nonRootEnablerImageKey string = "RELATED_IMAGE_NON_ROOT_ENABLER"
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
			Action:  runManager,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  enableWebhookFlag,
					Usage: "enableWebhook",
				},
			},
		},
		&cli.Command{
			Name:    "daemon",
			Aliases: []string{"d"},
			Usage:   "run the security-profiles-operator daemon",
			Action:  runDaemon,
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

	// cluster managers (need leader election)
	ctrlOpts := manager.Options{
		SyncPeriod:       &sync,
		LeaderElection:   true,
		LeaderElectionID: "selinux-operator-lock",
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

	if err := selinuxpolicyv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add core operator APIs to scheme")
	}

	if err := selinuxpolicy.Setup(ctx.Context, mgr, ctrl.Log.WithName("selinuxpolicy")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	if err := spod.Setup(ctx.Context, mgr, dt, ctrl.Log.WithName("spod-config")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	enableWHRaw := ctx.Value(enableWebhookFlag)
	enableWebhook, ok := enableWHRaw.(bool)
	if !ok {
		return errors.New("couldn't parse --enable-webhook flag")
	}
	if enableWebhook {
		setupLog.Info("enabling webhooks")
		if err := slns.Setup(mgr); err != nil {
			return errors.Wrap(err, "setup selinux namespace webhook")
		}
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	setupLog.Info("ending manager")
	return nil
}

func getTunables() (spod.DaemonTunables, error) {
	var dt spod.DaemonTunables
	restrictNS := os.Getenv(restrictNSKey)
	operatorImage := os.Getenv(operatorImageKey)
	if operatorImage == "" {
		return dt, errors.New("invalid operator image")
	}
	nonRootEnableImage := os.Getenv(nonRootEnablerImageKey)
	if operatorImage == "" {
		return dt, errors.New("invalid operator image")
	}

	dt.DaemonImage = operatorImage
	dt.NonRootEnablerImage = nonRootEnableImage
	dt.WatchNamespace = restrictNS
	return dt, nil
}

func runDaemon(ctx *cli.Context) error {
	// security-profiles-operator-daemon
	printInfo("spod")
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "get config")
	}

	sigHandler := ctrl.SetupSignalHandler()

	ctrlOpts := ctrl.Options{
		SyncPeriod: &sync,
	}

	if os.Getenv(restrictNSKey) != "" {
		ctrlOpts.Namespace = os.Getenv(restrictNSKey)
	}

	mgr, err := ctrl.NewManager(cfg, ctrlOpts)
	if err != nil {
		return errors.Wrap(err, "create manager")
	}

	if err := seccompprofilev1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return errors.Wrap(err, "add core operator APIs to scheme")
	}

	if err := profile.Setup(ctx.Context, mgr, ctrl.Log.WithName("profile")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	setupLog.Info("starting daemon")
	if err := mgr.Start(sigHandler); err != nil {
		return errors.Wrap(err, "SPOd error")
	}

	setupLog.Info("ending daemon")
	return nil
}
