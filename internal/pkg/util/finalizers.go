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

package util

import (
	"context"

	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// addFinalizer attempts to add a finalizer to an object if not present and update the object.
func AddFinalizer(ctx context.Context, c client.Client, pol client.Object, finalizer string) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return errors.Wrap(err, ErrGetProfile)
	}
	if controllerutil.ContainsFinalizer(pol, finalizer) {
		return nil
	}
	controllerutil.AddFinalizer(pol, finalizer)
	return c.Update(ctx, pol)
}

// removeFinalizer attempts to remove a finalizer from an object if present and update the object.
func RemoveFinalizer(ctx context.Context, c client.Client, pol client.Object, finalizer string) error {
	if err := c.Get(ctx, NamespacedName(pol.GetName(), pol.GetNamespace()), pol); err != nil {
		return errors.Wrap(err, ErrGetProfile)
	}
	if !controllerutil.ContainsFinalizer(pol, finalizer) {
		return nil
	}
	controllerutil.RemoveFinalizer(pol, finalizer)
	return c.Update(ctx, pol)
}
