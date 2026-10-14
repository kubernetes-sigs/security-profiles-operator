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
	"reflect"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// MaxWorkloads limits the workloads listed in the status of an object, so that
// an object used by very many pods stays far below the size limit of etcd and
// a write of the list stays cheap. The object keeps its finalizer as long as
// it lists any workload. Beyond the limit the list only tells some of the
// workloads: it gets filled up again from the current users once it runs
// empty, which keeps the finalizer while any user is left, and costs a
// lookup of the users only once per emptied list instead of once per removed
// workload.
const MaxWorkloads = 1000

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
	// Users returns the workloads which currently use the object. It fills
	// up a list once its last workload goes away, see MaxWorkloads. Without
	// it, the finalizer goes once the list is empty.
	Users func(context.Context, T) ([]string, error)
}

// Track adds the workload to the active workloads of the object, unless they
// list MaxWorkloads already, and ensures the finalizer.
func (t *Tracker[T]) Track(ctx context.Context, obj T, workload string) error {
	// A full list does not take the workload, which costs no read from the
	// API server if the cached object has the finalizer already. If the cache
	// is behind, the workload gets tracked on one of its next events or by a
	// later refill in Untrack.
	if obj.GetResourceVersion() != "" && len(*t.Workloads(obj)) >= MaxWorkloads &&
		controllerutil.ContainsFinalizer(obj, t.Finalizer) {
		return nil
	}

	base, written, err := t.updateWorkloads(ctx, obj, func(workloads []string) ([]string, error) {
		if slices.Contains(workloads, workload) || len(workloads) >= MaxWorkloads {
			return workloads, nil
		}

		return append(workloads, workload), nil
	})
	if err != nil {
		return err
	}

	// The written patch carried the resource version of base, so its
	// finalizers are the stored ones: with the finalizer, nothing is left to
	// do. Without it, the finalizer is read through the API server as well,
	// because the cache may still show the finalizer which an Untrack of the
	// last workload removed in the meantime, in which case nothing would
	// add it again.
	if written && controllerutil.ContainsFinalizer(base, t.Finalizer) {
		return nil
	}

	c := t.Client
	if written && t.Reader != nil {
		c = util.FreshReadClient(t.Client, t.Reader)
	}

	// AddFinalizer reads the object into the one it gets, which must not be
	// the one of the caller.
	withFinalizer, ok := obj.DeepCopyObject().(T)
	if !ok {
		return fmt.Errorf("copying %s %s", t.Kind, obj.GetName())
	}

	if err := util.RetryWithContext(ctx, func() error {
		return client.IgnoreNotFound(util.AddFinalizer(ctx, c, withFinalizer, t.Finalizer))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("adding finalizer: %w", err)
	}

	return nil
}

// Untrack removes the workload from the active workloads of the object and
// drops the finalizer once no workload is left. The list gets filled up with
// the other users of the object once its last workload goes away, see
// MaxWorkloads. If the users cannot be looked up then, the workload stays
// listed and the error is returned, so that the untrack gets retried, because
// the finalizer would go otherwise while users may be left.
func (t *Tracker[T]) Untrack(ctx context.Context, obj T, workload string) error {
	var usersErr error

	if _, _, err := t.updateWorkloads(ctx, obj, func(workloads []string) ([]string, error) {
		usersErr = nil

		remaining := slices.DeleteFunc(
			slices.Clone(workloads), func(w string) bool { return w == workload },
		)
		if len(remaining) == len(workloads) || len(remaining) > 0 || t.Users == nil {
			return remaining, nil
		}

		users, err := t.Users(ctx, obj)
		if err != nil {
			usersErr = fmt.Errorf("listing users of %s %s: %w", t.Kind, obj.GetName(), err)

			return workloads, nil
		}

		return fillUp(remaining, users, workload), nil
	}); err != nil {
		return err
	}

	if usersErr != nil {
		return usersErr
	}

	if err := util.RetryWithContext(ctx, func() error {
		current, found, err := t.get(ctx, obj)
		if err != nil || !found {
			return err
		}

		// The object gets written as read, so the update fails with a
		// conflict if another reconcile tracked a workload since the read,
		// and the retry then sees that workload. Reading the object again
		// from the cache could return a version which lists that workload
		// already, and removing the finalizer from it would succeed.
		if len(*t.Workloads(current)) > 0 ||
			!controllerutil.RemoveFinalizer(current, t.Finalizer) {
			return nil
		}

		return client.IgnoreNotFound(t.Client.Update(ctx, current))
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("removing finalizer: %w", err)
	}

	return nil
}

// fillUp appends the sorted users which are not listed yet, except the
// removed one, until the workloads list MaxWorkloads.
func fillUp(workloads, users []string, removed string) []string {
	for _, user := range slices.Sorted(slices.Values(users)) {
		if len(workloads) >= MaxWorkloads {
			break
		}

		if user != removed && !slices.Contains(workloads, user) {
			workloads = append(workloads, user)
		}
	}

	return workloads
}

// updateWorkloads writes the workloads which update returns for the current
// ones into the status of the object, if they changed. Only the workloads get
// patched, along with the resource version, so that a concurrent write fails
// with a conflict and the retry sees it. The provided object, usually the one
// of the cache, gets written first if it has a resource version and needs a
// change, so that tracking a workload costs no read from the API server. The
// object is read from the API server otherwise, because an outdated object
// may need no change, and for every retry. The provided object stays as it
// is. It returns the object the last attempt was based on, and whether that
// attempt wrote it.
func (t *Tracker[T]) updateWorkloads(
	ctx context.Context, obj T, update func([]string) ([]string, error),
) (base T, written bool, err error) {
	if obj.GetResourceVersion() != "" {
		written, err := t.writeWorkloads(ctx, obj, update)
		if written || (err != nil && !util.IsNotFoundOrConflict(err)) {
			return obj, written, err
		}
	}

	base = obj

	if err := util.RetryWithContext(ctx, func() error {
		current, found, err := t.get(ctx, obj)
		if err != nil || !found {
			return err
		}

		base = current
		written, err = t.writeWorkloads(ctx, current, update)

		return err
	}, util.IsNotFoundOrConflict); err != nil {
		return base, false, fmt.Errorf("updating %s status: %w", t.Kind, err)
	}

	return base, written, nil
}

// writeWorkloads patches the workloads which update returns for the ones of
// the object, if they changed. It returns whether it wrote them. The patch is
// written with a copy, so that the object keeps its workloads if the write
// fails.
func (t *Tracker[T]) writeWorkloads(
	ctx context.Context, obj T, update func([]string) ([]string, error),
) (bool, error) {
	workloads := *t.Workloads(obj)

	updated, err := update(slices.Clone(workloads))
	if err != nil {
		return false, err
	}

	if slices.Equal(updated, workloads) {
		return false, nil
	}

	changed, ok := obj.DeepCopyObject().(T)
	if !ok {
		return false, fmt.Errorf("copying %s %s", t.Kind, obj.GetName())
	}

	*t.Workloads(changed) = updated

	if err := t.Client.Status().Patch(
		ctx, changed, client.MergeFromWithOptions(obj, client.MergeFromWithOptimisticLock{}),
	); err != nil {
		return false, fmt.Errorf("updating %s status: %w", t.Kind, err)
	}

	return true, nil
}

// PodRequests returns reconcile requests for the pods of the active
// workloads, which are identified by namespace and name separated by a slash.
// Malformed identifiers are skipped.
func PodRequests(podIDs []string) []reconcile.Request {
	requests := make([]reconcile.Request, 0, len(podIDs))

	for _, podID := range podIDs {
		namespace, name, found := strings.Cut(podID, "/")
		if !found {
			continue
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: name, Namespace: namespace},
		})
	}

	return requests
}

// get reads the object of the provided one from the API server into a new
// object, so that no field of another version survives which the API server
// omits, like an empty list of workloads. It returns false if the object is
// gone.
func (t *Tracker[T]) get(ctx context.Context, obj T) (current T, found bool, err error) {
	current, ok := reflect.TypeAssert[T](reflect.New(reflect.TypeFor[T]().Elem()))
	if !ok {
		return current, false, fmt.Errorf("creating %s %s", t.Kind, obj.GetName())
	}

	if err := t.Reader.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
		if errors.IsNotFound(err) {
			return current, false, nil
		}

		return current, false, fmt.Errorf("retrieving %s: %w", t.Kind, err)
	}

	return current, true, nil
}
