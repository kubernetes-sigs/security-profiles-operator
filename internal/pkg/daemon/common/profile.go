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

package common

import (
	"context"
	"fmt"
	"sync"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ReportError reports err like Report does with its message.
func (e ErrorReporter) ReportError(obj runtime.Object, reason, action string, err error) {
	e.Report(obj, reason, action, err.Error())
}

// NewDeletionReasons returns the event reasons for removing a profile of a
// kind. A failed update of the node status has the same reason for all kinds.
func NewDeletionReasons(cannotUpdateProfile, cannotRemoveProfile string) DeletionReasons {
	return DeletionReasons{
		CannotUpdateProfile: cannotUpdateProfile,
		CannotRemoveProfile: cannotRemoveProfile,
		CannotUpdateStatus:  ReasonCannotUpdateStatus,
	}
}

// GetProfile reads the profile of key into obj. It returns false without an
// error if the profile is gone, which leaves nothing to reconcile, and an
// error wrapping ErrGetProfile if it cannot be read.
func GetProfile(
	ctx context.Context, c client.Reader, key client.ObjectKey, obj client.Object,
) (bool, error) {
	if err := c.Get(ctx, key, obj); err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}

		return false, fmt.Errorf("%w: %w", ErrGetProfile, err)
	}

	return true, nil
}

// UnsupportedReports remembers the profiles which got reported for a node
// which does not support their kind, so that each one gets reported once
// instead of on every reconcile. The zero value is ready to use.
type UnsupportedReports struct {
	// reported holds the UID of every reported profile, keyed by its
	// namespaced name.
	reported sync.Map
}

// ShouldReport returns true if the profile of key has to be reported for a
// node which does not support it. A profile gets reported once, and again if
// it is deleted and created again. obj receives the profile.
func (u *UnsupportedReports) ShouldReport(
	ctx context.Context, c client.Reader, key types.NamespacedName, obj client.Object,
) bool {
	if err := c.Get(ctx, key, obj); err != nil {
		if kerrors.IsNotFound(err) {
			u.reported.Delete(key)
		}

		return false
	}

	previous, reported := u.reported.Swap(key, obj.GetUID())

	return !reported || previous != obj.GetUID()
}
