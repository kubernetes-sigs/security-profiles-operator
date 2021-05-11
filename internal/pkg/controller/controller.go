/*
Copyright 2021 The Kubernetes Authors.

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

package controller

import (
	"context"
	"net/http"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// Controller is the interface every controller should fulfill.
type Controller interface {
	// Name returns the name of the controller.
	Name() string

	// SchemeBuilder returns the registered scheme of the controller.
	SchemeBuilder() *scheme.Builder

	// Setup is the initialization of the controller.
	Setup(context.Context, ctrl.Manager, *metrics.Metrics) error

	// Healthz is the liveness probe endpoint of the controller.
	Healthz(*http.Request) error
}
