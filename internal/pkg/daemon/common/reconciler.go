/*
Copyright 2026 The Kubernetes Authors.

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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	statusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	Wait                     = 10 * time.Second
	ErrGetProfile            = "cannot get profile"
	ReasonCannotUpdateStatus = "CannotUpdateNodeStatus"
)

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
func ReconcileDeletion(
	ctx context.Context,
	profile client.Object,
	nsc *nodestatus.StatusClient,
	cl client.Client,
	log logr.Logger,
	rec record.EventRecorder,
	reasons DeletionReasons,
	incError func(reason string),
	handleDeletion func() error,
) (reconcile.Result, error) {
	hasStatus, err := nsc.Exists(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("checking if node status exists: %w", err)
	}

	if hasStatus {
		isTerminating, getErr := nsc.Matches(ctx, statusv1alpha1.ProfileStateTerminating)
		if getErr != nil {
			log.Error(getErr, "couldn't get current status")

			return reconcile.Result{}, fmt.Errorf("getting status for deleted profile: %w", getErr)
		}

		if !isTerminating {
			log.Info("setting status to terminating")

			if err := nsc.SetNodeStatus(ctx, statusv1alpha1.ProfileStateTerminating); err != nil {
				log.Error(err, "cannot update profile status")
				incError(reasons.CannotUpdateProfile)
				rec.Event(profile, util.EventTypeWarning, reasons.CannotUpdateProfile, err.Error())

				return reconcile.Result{}, fmt.Errorf("updating status for deleted profile: %w", err)
			}

			return reconcile.Result{Requeue: true, RequeueAfter: Wait}, nil
		}
	}

	if controllerutil.ContainsFinalizer(profile, util.HasActivePodsFinalizerString) {
		log.Info("cannot delete profile in use by pod, requeuing")

		return reconcile.Result{RequeueAfter: Wait}, nil
	}

	if err := handleDeletion(); err != nil {
		log.Error(err, "cannot delete profile")
		incError(reasons.CannotRemoveProfile)
		rec.Event(profile, util.EventTypeWarning, reasons.CannotRemoveProfile, err.Error())

		return ctrl.Result{}, fmt.Errorf("handling deletion for deleted profile: %w", err)
	}

	if err := nsc.Remove(ctx, cl); err != nil {
		log.Error(err, "cannot remove node status/finalizer from profile")
		incError(reasons.CannotUpdateStatus)
		rec.Event(profile, util.EventTypeWarning, reasons.CannotUpdateStatus, err.Error())

		return ctrl.Result{}, fmt.Errorf("deleting node status/finalizer for deleted profile: %w", err)
	}

	return ctrl.Result{}, nil
}

// EnsureNodeStatus checks whether the node status for a profile exists and
// creates it if it does not. Returns (true, requeueResult, nil) when the
// status was just created, signaling that the caller should requeue.
func EnsureNodeStatus(
	ctx context.Context,
	nsc *nodestatus.StatusClient,
	log logr.Logger,
) (bool, reconcile.Result, error) {
	exists, err := nsc.Exists(ctx)
	if err != nil {
		return false, reconcile.Result{}, fmt.Errorf("checking if node status exists: %w", err)
	}

	if !exists {
		if err := nsc.Create(ctx); err != nil {
			return false, reconcile.Result{}, fmt.Errorf("cannot ensure node status: %w", err)
		}

		log.Info("Created an initial status for this node")

		return true, reconcile.Result{RequeueAfter: Wait}, nil
	}

	return false, reconcile.Result{}, nil
}
