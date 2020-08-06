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
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"

	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
	"sigs.k8s.io/seccomp-operator/internal/pkg/controllers/profile"
	"sigs.k8s.io/seccomp-operator/internal/pkg/initialize"
	"sigs.k8s.io/seccomp-operator/internal/pkg/version"
)

const jsonFlag string = "json"

var (
	sync     = time.Second * 30
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	ctrl.SetLogger(klogr.New())

	app := cli.NewApp()
	app.Name = config.OperatorName
	app.Usage = "Kubernetes Seccomp Operator"
	app.Description = "The Seccomp Operator makes it easier for cluster admins " +
		"to manage their seccomp profiles and apply them to Kubernetes' workloads."
	app.Version = version.Get().GitVersion
	app.Action = run
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
			Name:    "initialize",
			Aliases: []string{"init", "i"},
			Usage:   "initialize the operator directories and set the right permissions",
			Action: func(c *cli.Context) error {
				return errors.Wrap(initialize.SetupRootless(
					config.KubeletSeccompRootPath,
					filepath.Join("/var/lib", config.OperatorName),
					config.ProfilesRootPath,
					2000,
				), "initialize rootless deployment")
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		setupLog.Error(err, "running seccomp-operator")
		os.Exit(1)
	}
}

func run(*cli.Context) error {
	v := version.Get()
	setupLog.Info(
		"starting seccomp-operator",
		"gitVersion", v.GitVersion,
		"gitCommit", v.GitCommit,
		"gitTreeState", v.GitTreeState,
		"buildDate", v.BuildDate,
		"goVersion", v.GoVersion,
		"compiler", v.Compiler,
		"platform", v.Platform,
	)
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "get config")
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		SyncPeriod: &sync,
	})
	if err != nil {
		return errors.Wrap(err, "create manager")
	}

	if err := profile.Setup(mgr, ctrl.Log.WithName("profile")); err != nil {
		return errors.Wrap(err, "setup profile controller")
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	return nil
}
