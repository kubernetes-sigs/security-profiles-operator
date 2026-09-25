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

package recordingtracker

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/common"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// recordingStatusReconciler reports on the Ready condition of a
// ProfileRecording whether its kind and recorder can be combined. The
// recording webhook skips invalid recordings, so this is the only place where
// the user can see it.
type recordingStatusReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
}

func (r *recordingStatusReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	return reconcile.Result{}, retry.RetryOnConflict(retry.DefaultRetry, func() error {
		recording := &profilerecordingapi.ProfileRecording{}
		if err := r.reader.Get(ctx, req.NamespacedName, recording); err != nil {
			return client.IgnoreNotFound(err)
		}

		condition := common.Available()
		if err := recording.ValidateRecorderKindCombination(); err != nil {
			condition = common.Unavailable(err.Error())
		}

		updated := recording.DeepCopy()
		updated.Status.SetConditionForGeneration(&condition, recording.GetGeneration())

		if reflect.DeepEqual(recording.Status, updated.Status) {
			return nil
		}

		r.log.V(config.VerboseLevel).
			Info("Updating recording condition", "recording", req.NamespacedName,
				"reason", condition.Reason)

		if err := r.client.Status().Update(ctx, updated); err != nil {
			return fmt.Errorf("updating recording status: %w", err)
		}

		return nil
	})
}
