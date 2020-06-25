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
	"time"

	"github.com/pkg/errors"
	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/saschagrunert/seccomp-operator/internal/pkg/controllers/profile"
)

const (
	namespaceToWatchDefault string = "seccomp-operator"
	namespaceToWatchKey     string = "NAMESPACE_TO_WATCH"
)

var (
	sync     = time.Second * 30
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	ctrl.SetLogger(klogr.New())

	if err := run(); err != nil {
		setupLog.Error(err, "running seccomp-operator")
		os.Exit(1)
	}
}

func run() error {
	setupLog.Info("starting seccomp-operator")
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return errors.Wrap(err, "cannot get config")
	}

	namespaceToWatch := namespaceToWatchDefault
	if os.Getenv(namespaceToWatchKey) != "" {
		namespaceToWatch = os.Getenv(namespaceToWatchKey)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		SyncPeriod: &sync,
		Namespace:  namespaceToWatch,
	})

	if err != nil {
		return errors.Wrap(err, "cannot create manager")
	}

	if err := profile.Setup(mgr, ctrl.Log.WithName("profile")); err != nil {
		return errors.Wrap(err, "cannot setup profile controller")
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return errors.Wrap(err, "controller manager error")
	}

	return nil
}
