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

	"k8s.io/klog/klogr"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/saschagrunert/seccomp-operator/controllers/profile"
)

const (
	namespaceToWatchDefault string = "seccomp-operator"
)

var (
	sync     = time.Second * 30
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	ctrl.SetLogger(klogr.New())

	setupLog.Info("starting seccomp-operator")
	cfg, err := ctrl.GetConfig()
	if err != nil {
		setupLog.Error(err, "cannot get config")
		os.Exit(1)
	}

	namespaceToWatch := namespaceToWatchDefault
	if os.Getenv("NAMESPACE_TO_WATCH") != "" {
		namespaceToWatch = os.Getenv("NAMESPACE_TO_WATCH")
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		SyncPeriod: &sync,
		Namespace:  namespaceToWatch,
	})
	if err != nil {
		setupLog.Error(err, "cannot create manager")
		os.Exit(1)
	}

	if err := profile.Setup(mgr, ctrl.Log.WithName("profile")); err != nil {
		setupLog.Error(err, "cannot setup profile controller")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "controller manager error")
		os.Exit(1)
	}
}
