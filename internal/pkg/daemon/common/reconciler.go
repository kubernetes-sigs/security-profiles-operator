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
	"errors"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	Wait                     = 10 * time.Second
	ReasonCannotUpdateStatus = "CannotUpdateNodeStatus"

	// stuckFinalizerWarningAge is the deletion age after which a profile that
	// is still in use by pods gets a warning in the logs.
	stuckFinalizerWarningAge = 10 * time.Minute

	// InUseRetry is the time after which a disabled profile which pods still
	// use is checked again, so that it gets removed once they are gone.
	InUseRetry = time.Minute
)

// InUse returns true if running pods still use the profile. Removing it from
// the node would break them, for example on a container restart.
func InUse(profile client.Object) bool {
	return controllerutil.ContainsFinalizer(profile, util.HasActivePodsFinalizerString)
}

// ErrGetProfile is returned if a profile cannot be retrieved.
var ErrGetProfile = errors.New("cannot get profile")

// ErrorReporter increments the error metric of a controller and records a
// warning event for the affected object.
type ErrorReporter struct {
	Record   util.EventRecorder
	IncError func(reason string)
}

// Report increments the error metric for reason and records a warning event
// with the provided action and message on obj.
func (e ErrorReporter) Report(obj runtime.Object, reason, action, msg string) {
	if e.IncError != nil {
		e.IncError(reason)
	}

	if e.Record != nil {
		e.Record.Eventf(obj, nil, util.EventTypeWarning, reason, action, "%s", msg)
	}
}

// DeletionReasons holds profile-type-specific event reason strings used
// during deletion reconciliation.
type DeletionReasons struct {
	CannotUpdateProfile string
	CannotRemoveProfile string
	CannotUpdateStatus  string
}

// ReconcileDeletion implements the shared deletion reconciliation flow for
// profile controllers. Profile-specific behavior is injected via callbacks:
// incError increments the appropriate error metric, and handleDeletion
// performs the actual profile removal (e.g., file delete or kernel unload).
// handleDeletion can request a requeue, for example to wait for an
// asynchronous removal, in which case the node status is kept.
func ReconcileDeletion(
	ctx context.Context,
	profile client.Object,
	nsc *nodestatus.StatusClient,
	cl client.Client,
	log logr.Logger,
	rec util.EventRecorder,
	reasons DeletionReasons,
	incError func(reason string),
	handleDeletion func() (reconcile.Result, error),
) (reconcile.Result, error) {
	reporter := ErrorReporter{Record: rec, IncError: incError}

	// The node status API removes the finalizer of this node only after the
	// profile is gone from the node, so without it there is nothing left to
	// do. The node status alone is not a reliable signal: a foreground
	// deletion removes the owned node statuses before the profile.
	if !nsc.FinalizerExists() {
		return ctrl.Result{}, nil
	}

	hasStatus, err := nsc.Exists(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking if node status exists: %w", err)
	}

	if hasStatus {
		isTerminating, getErr := nsc.Matches(ctx, secprofnodestatusapi.ProfileStateTerminating)
		if getErr != nil {
			log.Error(getErr, "couldn't get current status")

			return reconcile.Result{}, fmt.Errorf("getting status for deleted profile: %w", getErr)
		}

		if !isTerminating {
			log.Info("setting status to terminating")

			if err := nsc.SetNodeStatus(
				ctx,
				secprofnodestatusapi.ProfileStateTerminating,
			); err != nil {
				log.Error(err, "cannot update profile status")
				reporter.Report(
					profile,
					reasons.CannotUpdateProfile,
					util.EventActionUpdate,
					err.Error(),
				)

				return reconcile.Result{}, fmt.Errorf(
					"updating status for deleted profile: %w",
					err,
				)
			}

			return reconcile.Result{RequeueAfter: Wait}, nil
		}
	}

	if InUse(profile) {
		if ts := profile.GetDeletionTimestamp(); ts != nil {
			age := time.Since(ts.Time)
			if age > stuckFinalizerWarningAge {
				log.Info("WARNING: profile stuck with active-pods finalizer for over 10 minutes, "+
					"check if pods using this profile are still running",
					"deletionAge", age.Round(time.Second).String())
			}
		}

		log.Info("cannot delete profile in use by pod, requeuing")

		return reconcile.Result{RequeueAfter: Wait}, nil
	}

	res, err := handleDeletion()
	if err != nil {
		log.Error(err, "cannot delete profile")
		reporter.Report(profile, reasons.CannotRemoveProfile, util.EventActionRemove, err.Error())

		// The result is dropped: controller-runtime ignores a requeue
		// returned with an error and retries with backoff instead.
		return ctrl.Result{}, fmt.Errorf("handling deletion for deleted profile: %w", err)
	}

	if res.RequeueAfter > 0 {
		log.Info("Requeuing the deletion to make sure the profile is gone")

		return res, nil
	}

	if err := nsc.Remove(ctx, cl); err != nil {
		log.Error(err, "cannot remove node status/finalizer from profile")
		reporter.Report(profile, reasons.CannotUpdateStatus, util.EventActionUpdate, err.Error())

		return ctrl.Result{}, fmt.Errorf(
			"deleting node status/finalizer for deleted profile: %w",
			err,
		)
	}

	return ctrl.Result{}, nil
}

// EnsureNodeStatusOrRequeue creates the node status of a profile if it does
// not exist. It returns true with the result to return if the reconcile has
// to stop here: the status got created, so the profile is reconciled again
// after Wait, or the status could not be ensured.
func EnsureNodeStatusOrRequeue(
	ctx context.Context,
	nsc *nodestatus.StatusClient,
	log logr.Logger,
) (res reconcile.Result, stop bool, err error) {
	created, _, err := EnsureNodeStatus(ctx, nsc, log)
	if err != nil {
		return reconcile.Result{}, true, err
	}

	if created {
		return reconcile.Result{RequeueAfter: Wait}, true, nil
	}

	return reconcile.Result{}, false, nil
}

// MarkInstalled sets the node status of the profile to installed unless it is
// already, and returns true if it changed. A failure to read or update the
// status is reported on the profile with ReasonCannotUpdateStatus.
func MarkInstalled(
	ctx context.Context,
	profile client.Object,
	nsc *nodestatus.StatusClient,
	log logr.Logger,
	reporter ErrorReporter,
) (bool, error) {
	isInstalled, err := nsc.Matches(ctx, secprofnodestatusapi.ProfileStateInstalled)
	if err != nil {
		log.Error(err, "couldn't get current status")

		return false, fmt.Errorf("getting status for installed profile: %w", err)
	}

	if isInstalled {
		log.Info("Already in the expected Installed state")

		return false, nil
	}

	if err := nsc.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateInstalled); err != nil {
		log.Error(err, "cannot update node status")
		reporter.Report(profile, ReasonCannotUpdateStatus, util.EventActionUpdate, err.Error())

		return false, fmt.Errorf("setting node status to installed: %w", err)
	}

	return true, nil
}

// ReconcileDisabled removes a disabled profile from the node, which may have
// installed it before it got disabled. remove takes the profile off the node
// and afterRemove, which may be nil, runs once it is gone, before the node
// status moves to disabled. A profile which pods still use is checked again
// after InUseRetry, because removing it would break them.
func ReconcileDisabled(
	ctx context.Context,
	profile client.Object,
	nsc *nodestatus.StatusClient,
	log logr.Logger,
	reporter ErrorReporter,
	reasons DeletionReasons,
	remove func() error,
	afterRemove func() error,
) (reconcile.Result, error) {
	state, err := nsc.State(ctx)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("getting node status: %w", err)
	}

	if state == secprofnodestatusapi.ProfileStateDisabled {
		log.Info("Profile is disabled, skipping")

		return reconcile.Result{}, nil
	}

	if InUse(profile) {
		log.Info("Not removing disabled profile which is in use by pods, requeuing")

		return reconcile.Result{RequeueAfter: InUseRetry}, nil
	}

	if err := remove(); err != nil {
		log.Error(err, "cannot remove disabled profile")
		reporter.Report(profile, reasons.CannotRemoveProfile, util.EventActionRemove, err.Error())

		return reconcile.Result{}, fmt.Errorf("removing disabled profile: %w", err)
	}

	if afterRemove != nil {
		if err := afterRemove(); err != nil {
			reporter.Report(
				profile,
				reasons.CannotUpdateStatus,
				util.EventActionUpdate,
				err.Error(),
			)

			return reconcile.Result{}, fmt.Errorf("recording profile removal: %w", err)
		}
	}

	if err := nsc.SetNodeStatus(ctx, secprofnodestatusapi.ProfileStateDisabled); err != nil {
		reporter.Report(profile, reasons.CannotUpdateStatus, util.EventActionUpdate, err.Error())

		return reconcile.Result{}, fmt.Errorf("setting node status to disabled: %w", err)
	}

	log.Info("Removed disabled profile from the node")

	return reconcile.Result{}, nil
}

// EnsureNodeStatus checks whether the node status for a profile exists and
// creates it if it does not. created is true when the status was just
// created, and wasMigrated is true if it replaced a legacy status object
// from a previous operator version.
func EnsureNodeStatus(
	ctx context.Context,
	nsc *nodestatus.StatusClient,
	log logr.Logger,
) (created, wasMigrated bool, err error) {
	exists, err := nsc.Exists(ctx)
	if err != nil {
		return false, false, fmt.Errorf("checking if node status exists: %w", err)
	}

	if exists {
		// A status created by an earlier release may come with the legacy
		// finalizer of this node only, next to which the current one is
		// added. The legacy one can be shared with other nodes, so it stays.
		if err := nsc.MigrateLegacyFinalizer(ctx); err != nil {
			return false, false, err
		}

		return false, false, nil
	}

	wasMigrated, err = nsc.Create(ctx)
	if err != nil {
		return false, false, fmt.Errorf("cannot ensure node status: %w", err)
	}

	log.Info("Created an initial status for this node")

	return true, wasMigrated, nil
}
