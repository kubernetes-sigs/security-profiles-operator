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

// Package workloadtracker keeps the active workloads in the status of an
// object, like a profile binding or recording, and a finalizer on the object
// while it has any.
package workloadtracker

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Tracker tracks the workloads of objects of the type T.
type Tracker[T client.Object] struct {
	// Client writes the objects.
	Client client.Client
	// Reader reads the objects from the API server, so that a retry after a
	// conflict sees the object which won it.
	Reader client.Reader
	// Finalizer keeps an object while it has active workloads.
	Finalizer string
	// Kind names the objects in errors.
	Kind string
	// Workloads returns the active workloads in the status of the object.
	Workloads func(T) *[]string
}

// Track adds the workload to the active workloads of the object and ensures
// the finalizer.
func (t *Tracker[T]) Track(ctx context.Context, obj T, workload string) error {
	if err := t.updateWorkloads(ctx, obj, func(workloads []string) []string {
		if slices.Contains(workloads, workload) {
			return workloads
		}

		return append(workloads, workload)
	}); err != nil {
		return err
	}

	if err := util.RetryWithContext(ctx, func() error {
		return client.IgnoreNotFound(util.AddFinalizer(ctx, t.Client, obj, t.Finalizer))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("adding finalizer: %w", err)
	}

	return nil
}

// Untrack removes the workload from the active workloads of the object and
// drops the finalizer once no workload is left.
func (t *Tracker[T]) Untrack(ctx context.Context, obj T, workload string) error {
	if err := t.updateWorkloads(ctx, obj, func(workloads []string) []string {
		return slices.DeleteFunc(workloads, func(w string) bool { return w == workload })
	}); err != nil {
		return err
	}

	if err := util.RetryWithContext(ctx, func() error {
		if found, err := t.get(ctx, obj); err != nil || !found {
			return err
		}

		// The object gets written as read, so the update fails with a
		// conflict if another reconcile tracked a workload since the read,
		// and the retry then sees that workload. Reading the object again
		// from the cache could return a version which lists that workload
		// already, and removing the finalizer from it would succeed.
		if len(*t.Workloads(obj)) > 0 || !controllerutil.RemoveFinalizer(obj, t.Finalizer) {
			return nil
		}

		return client.IgnoreNotFound(t.Client.Update(ctx, obj))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	return nil
}

// updateWorkloads writes the workloads which update returns for the current
// ones into the status of the object, if they changed.
func (t *Tracker[T]) updateWorkloads(
	ctx context.Context, obj T, update func([]string) []string,
) error {
	if err := util.RetryWithContext(ctx, func() error {
		if found, err := t.get(ctx, obj); err != nil || !found {
			return err
		}

		workloads := t.Workloads(obj)

		updated := update(slices.Clone(*workloads))
		if slices.Equal(updated, *workloads) {
			return nil
		}

		*workloads = updated

		if err := t.Client.Status().Update(ctx, obj); err != nil {
			return fmt.Errorf("updating %s status: %w", t.Kind, err)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating %s status: %w", t.Kind, err)
	}

	return nil
}

// get reads the object from the API server. It returns false if the object
// is gone.
func (t *Tracker[T]) get(ctx context.Context, obj T) (bool, error) {
	if err := t.Reader.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}

		return false, fmt.Errorf("retrieving %s: %w", t.Kind, err)
	}

	return true, nil
}
