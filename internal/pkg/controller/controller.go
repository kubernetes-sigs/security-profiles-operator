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

package controller

import (
	"context"
	"net/http"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcontroller "sigs.k8s.io/controller-runtime/pkg/controller"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// ctxKey is the type of the context keys of this package.
type ctxKey string

// MaxConcurrentReconcilesKey is the context key under which the manager
// passes the number of concurrent reconciles per controller to Setup.
const MaxConcurrentReconcilesKey ctxKey = "MaxConcurrentReconciles"

// DefaultMaxConcurrentReconciles is the number of concurrent reconciles of
// a controller if the context does not carry one.
const DefaultMaxConcurrentReconciles = 4

// WithMaxConcurrentReconciles returns a context carrying the number of
// concurrent reconciles for the controllers, see Options.
func WithMaxConcurrentReconciles(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, MaxConcurrentReconcilesKey, n)
}

// MaxConcurrentReconciles returns the number of concurrent reconciles of the
// context, or the default if it does not carry a positive one.
func MaxConcurrentReconciles(ctx context.Context) int {
	if n, ok := ctx.Value(MaxConcurrentReconcilesKey).(int); ok && n > 0 {
		return n
	}

	return DefaultMaxConcurrentReconciles
}

// Options returns the options of the pod driven controllers, which reconcile
// many objects and therefore run several reconciles concurrently. The
// controllers write with conflict retries, so concurrent reconciles of
// different objects are safe.
func Options(ctx context.Context) ctrlcontroller.Options {
	return ctrlcontroller.Options{MaxConcurrentReconciles: MaxConcurrentReconciles(ctx)}
}

// Controller is the interface every controller should fulfill.
type Controller interface {
	// Name returns the name of the controller.
	Name() string

	// SchemeBuilder returns the registered scheme of the controller.
	SchemeBuilder() runtime.SchemeBuilder

	// Setup is the initialization of the controller.
	Setup(context.Context, ctrl.Manager, *metrics.Metrics) error

	// Healthz is the liveness probe endpoint of the controller.
	Healthz(*http.Request) error
}
