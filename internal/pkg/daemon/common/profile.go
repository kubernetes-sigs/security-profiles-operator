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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// ReportError reports err like Report does with its message.
func (e ErrorReporter) ReportError(obj runtime.Object, reason, action string, err error) {
	e.Report(obj, reason, action, err.Error())
}

// ReportRelated is like ReportError for an event on obj which is about the
// related object, like a profile which a node cannot install. Without the
// related object, the events of all profiles would look the same.
func (e ErrorReporter) ReportRelated(
	obj, related runtime.Object, reason, action string, err error,
) {
	if e.IncError != nil {
		e.IncError(reason)
	}

	if e.Record != nil {
		e.Record.Eventf(obj, related, corev1.EventTypeWarning, reason, action, "%s", err.Error())
	}
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

// Reports remembers the last report about each profile, so that the periodic
// resyncs of the daemon do not repeat an unchanged report on every reconcile.
// A report is a comparable value which tells apart what got reported, like
// the UID and the generation of the profile with the reason. The zero value
// is ready to use.
type Reports[V comparable] struct {
	// reported holds the last report, keyed by the namespaced name of the
	// profile.
	reported sync.Map
}

// ShouldReport returns true if report differs from the last one of the
// profile of key, which it replaces.
func (r *Reports[V]) ShouldReport(key types.NamespacedName, report V) bool {
	previous, reported := r.reported.Swap(key, report)

	return !reported || previous != report
}

// Reported returns the last report of the profile of key, and false if there
// is none.
func (r *Reports[V]) Reported(key types.NamespacedName) (report V, ok bool) {
	value, ok := r.reported.Load(key)
	if !ok {
		return report, false
	}

	report, ok = value.(V)

	return report, ok
}

// Forget makes the next report of the profile of key get reported.
func (r *Reports[V]) Forget(key types.NamespacedName) {
	r.reported.Delete(key)
}

// UnsupportedReports remembers the profiles which got reported for a node
// which does not support their kind, so that each one gets reported once
// instead of on every reconcile. The zero value is ready to use.
type UnsupportedReports struct {
	// reported holds the UID of every reported profile.
	reported Reports[types.UID]
}

// check returns whether the profile of key has to be reported for a node
// which does not support it, and whether it is gone. A profile gets reported
// once, and again if it is deleted and created again. obj receives the
// profile.
func (u *UnsupportedReports) check(
	ctx context.Context, c client.Reader, key types.NamespacedName, obj client.Object,
) (report, gone bool) {
	if err := c.Get(ctx, key, obj); err != nil {
		if kerrors.IsNotFound(err) {
			u.reported.Forget(key)

			return false, true
		}

		return false, false
	}

	return u.reported.ShouldReport(key, obj.GetUID()), false
}

// Report logs that the node cannot install the profile of key, because it
// does not support its kind, and reports it as a warning event on the node
// with reason, which refers to the profile as related object. Every profile
// gets reported once, and again if it is deleted and created again, the
// further reconciles only log it verbosely. obj receives the profile. Report
// returns true if the profile is gone, so that the caller can drop what it
// kept about it.
func (u *UnsupportedReports) Report(
	ctx context.Context,
	c client.Reader,
	key types.NamespacedName,
	obj client.Object,
	l logr.Logger,
	reporter ErrorReporter,
	nodeName, reason string,
	err error,
) (gone bool) {
	report, gone := u.check(ctx, c, key, obj)
	if !report {
		l.V(config.VerboseLevel).Info("Profile not added", "reason", err.Error())

		return gone
	}

	l.Error(err, "Profile not added")
	reporter.ReportRelated(util.EventNode(nodeName), obj, reason, util.EventActionInstall, err)

	return false
}

// ReconcileUnsupported reconciles a profile on a node which is known not to
// support its kind, like after a reboot without the LSM. A profile which is
// being deleted gets released, see ReleaseUnsupported. Every other profile
// gets a node status which is marked as unsupported, see
// nodestatus.StatusClient.MarkUnsupported: the error state with the message
// of unsupportedErr, the disabled state for a disabled profile and the
// partial state for a partial one. The manager counts the node as reported
// then, but leaves its state out of the one of the profile. Nothing gets
// written for a profile which could not be read, the next resync tries again.
func ReconcileUnsupported(
	ctx context.Context,
	c client.Client,
	reader client.Reader,
	profile profilebase.SecurityProfileBase,
	nodeName string,
	written *nodestatus.WrittenStates,
	unsupportedErr error,
) error {
	if profile.GetName() == "" {
		return nil
	}

	if !profile.GetDeletionTimestamp().IsZero() {
		return ReleaseUnsupported(ctx, c, reader, profile, nodeName, written)
	}

	nsc, err := nodestatus.NewForProfileOnNode(profile, c, nodeName)
	if err != nil {
		return fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	nsc.WithAPIReader(reader)
	nsc.WithWrittenStates(written)

	state, message := secprofnodestatusapi.ProfileStateError, unsupportedErr.Error()

	switch {
	case profile.IsDisabled() && !profile.IsPartial():
		state, message = secprofnodestatusapi.ProfileStateDisabled, ""
	case profile.IsPartial():
		state, message = secprofnodestatusapi.ProfileStatePartial, ""
	}

	if err := nsc.MarkUnsupported(ctx, state, message); err != nil {
		return fmt.Errorf("setting the node status of an unsupported profile: %w", err)
	}

	return nil
}

// ReleaseUnsupported removes the finalizer and the node status of the node
// from a profile which is being deleted while the node does not support its
// kind, like after a reboot without the LSM. The profile cannot be installed
// on the node then, so there is nothing to remove from the node, but the
// finalizer which the node added while it supported the kind would keep the
// profile around until the node is gone. The retries of a conflicting write
// read the profile through the reader, like the node status client does.
func ReleaseUnsupported(
	ctx context.Context,
	c client.Client,
	reader client.Reader,
	profile profilebase.SecurityProfileBase,
	nodeName string,
	written *nodestatus.WrittenStates,
) error {
	if profile.GetDeletionTimestamp().IsZero() {
		return nil
	}

	nsc, err := nodestatus.NewForProfileOnNode(profile, c, nodeName)
	if err != nil {
		return fmt.Errorf("cannot create nodeStatus: %w", err)
	}

	// The state written to the node status is forgotten along with it.
	nsc.WithWrittenStates(written)

	if !nsc.FinalizerExists() {
		return nil
	}

	nsc.WithAPIReader(reader)

	if err := nsc.Remove(ctx, c); err != nil {
		return fmt.Errorf("releasing a profile which the node does not support: %w", err)
	}

	return nil
}
