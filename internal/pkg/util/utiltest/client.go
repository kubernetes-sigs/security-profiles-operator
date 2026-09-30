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

// Package utiltest provides helpers for unit tests: schemes, fake clients,
// event assertions and golden files.
package utiltest

import (
	"context"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// NewFakeClient returns a fake client with the scheme of NewScheme and the
// objects, whose calls go through funcs first.
func NewFakeClient(t *testing.T, funcs *interceptor.Funcs, objs ...client.Object) client.WithWatch {
	t.Helper()

	return fake.NewClientBuilder().
		WithScheme(NewScheme(t)).
		WithObjects(objs...).
		WithInterceptorFuncs(*funcs).
		Build()
}

// GetReturns returns a Get interceptor which does not ask the client, but
// only applies fns to the object and returns err.
func GetReturns(err error, fns ...func(client.Object)) func(
	context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption,
) error {
	return func(
		_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption,
	) error {
		for _, fn := range fns {
			fn(obj)
		}

		return err
	}
}

// CreateReturns returns a Create interceptor which does not ask the client,
// but only returns err.
func CreateReturns(
	err error,
) func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
	return func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
		return err
	}
}

// DeleteReturns returns a Delete interceptor which does not ask the client,
// but only returns err.
func DeleteReturns(
	err error,
) func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
	return func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
		return err
	}
}

// UpdateReturns returns an Update interceptor which does not ask the client,
// but only returns err.
func UpdateReturns(
	err error,
) func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
	return func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
		return err
	}
}

// SubResourceUpdateReturns returns a SubResourceUpdate interceptor which does
// not ask the client, but only returns err.
func SubResourceUpdateReturns(err error) func(
	context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption,
) error {
	return func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
		return err
	}
}
