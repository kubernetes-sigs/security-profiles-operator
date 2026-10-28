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

package spod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/seccompcheck"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const reasonInvalidSPODConfig string = "InvalidSeccompSPODConfig"

// enforcedAllowListAnnotation is set on the SPOD to the hash of the allow
// lists which reconcileAllowList enforced last. The SPOD passes the predicate
// of the controller again on every restart of the manager, which must not
// delete the profiles created since then: the daemons only reject those.
const enforcedAllowListAnnotation = "spo.x-k8s.io/enforced-allow-list-hash"

// setupAllowList adds the controller which deletes the seccomp profiles that
// the allow lists of the SPOD reject. It runs in the manager, so that the
// deletion happens once for the cluster instead of on every node, and the
// daemons do not need the permission to delete profiles. The daemons validate
// every profile again on their own when the allow lists change, and reject
// the ones which are not allowed without deleting them.
func (r *ReconcileSPOd) setupAllowList(
	mgr ctrl.Manager,
	inOperatorNamespace builder.Predicates,
) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.Name()+"-allowed-syscalls").
		For(
			&spodapi.SecurityProfilesOperatorDaemon{},
			inOperatorNamespace,
			builder.WithPredicates(seccompcheck.AllowListChangedPredicate{}),
		).
		Complete(reconcile.Func(r.reconcileAllowList))
}

// reconcileAllowList deletes the seccomp profiles which use syscalls that the
// SPOD does not allow.
func (r *ReconcileSPOd) reconcileAllowList(
	ctx context.Context, req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	if err := r.client.Get(ctx, req.NamespacedName, spod); err != nil {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	}

	// The daemons only follow the allow lists of the SPOD named spod, see
	// Reconcile.
	if spod.GetName() != config.SPOdName {
		return reconcile.Result{}, nil
	}

	// The patches below decode the stored SPOD into spod, whose allow lists
	// may have changed since, so the enforced ones are copied first.
	security := spod.Spec.Security.DeepCopy()

	enforced := allowListHash(security)
	if spod.GetAnnotations()[enforcedAllowListAnnotation] == enforced {
		return reconcile.Result{}, nil
	}

	// The hash of the allow lists enforced before goes first, so that an
	// enforcement which does not complete leaves none. Setting those allow
	// lists again then enforces them again, like after removing them.
	if _, ok := spod.GetAnnotations()[enforcedAllowListAnnotation]; ok {
		if err := r.setEnforcedAllowList(ctx, spod, ""); err != nil {
			return reconcile.Result{}, err
		}
	}

	if len(security.AllowedSyscalls) == 0 {
		return reconcile.Result{}, nil
	}

	// An invalid configuration rejects every profile. Deleting all of them
	// because of a mistake in the SPOD cannot be undone.
	if _, err := seccompcheck.CheckedActions(security.AllowedSeccompActions); err != nil {
		r.log.Error(err, "Not deleting seccomp profiles because of an invalid SPOD configuration")
		r.record.Eventf(
			spod, nil, corev1.EventTypeWarning, reasonInvalidSPODConfig, util.EventActionUpdate,
			"Invalid allowedSeccompActions, no seccomp profile gets installed: %s", err.Error(),
		)

		return reconcile.Result{}, nil
	}

	profiles := &seccompprofileapi.SeccompProfileList{}
	if err := r.client.List(ctx, profiles); err != nil {
		return reconcile.Result{}, fmt.Errorf("listing seccomp profiles: %w", err)
	}

	// All profiles get checked before any gets deleted, because a deleted
	// base profile could not be resolved for the profiles derived from it.
	var rejected []*seccompprofileapi.SeccompProfile

	for i := range profiles.Items {
		if r.notAllowed(ctx, &profiles.Items[i], security) {
			rejected = append(rejected, &profiles.Items[i])
		}
	}

	var errs []error

	for _, sp := range rejected {
		if err := r.client.Delete(ctx, sp); err != nil && !k8serrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("deleting not allowed seccomp profile %s: %w",
				sp.GetName(), err))
		}
	}

	if len(errs) > 0 {
		return reconcile.Result{}, errors.Join(errs...)
	}

	return reconcile.Result{}, r.setEnforcedAllowList(ctx, spod, enforced)
}

// allowListHash returns the hash of the allow lists, or an empty string if
// no syscalls are allowed, which does not enforce anything. Like for
// seccompcheck.AllowListChanged, the order and duplicates of the entries do
// not matter.
func allowListHash(security *spodapi.SPODSecurityConfig) string {
	if len(security.AllowedSyscalls) == 0 {
		return ""
	}

	actions := sets.List(sets.New(security.AllowedSeccompActions...))
	actionNames := make([]string, 0, len(actions))

	for _, action := range actions {
		actionNames = append(actionNames, string(action))
	}

	hash := sha256.Sum256([]byte(
		strings.Join(sets.List(sets.New(security.AllowedSyscalls...)), ",") +
			"\n" + strings.Join(actionNames, ","),
	))

	return hex.EncodeToString(hash[:])
}

// setEnforcedAllowList records the hash of the enforced allow lists on the
// SPOD, an empty hash removes it.
func (r *ReconcileSPOd) setEnforcedAllowList(
	ctx context.Context, spod *spodapi.SecurityProfilesOperatorDaemon, hash string,
) error {
	patch := client.MergeFrom(spod.DeepCopy())

	annotations := spod.GetAnnotations()
	if hash == "" {
		delete(annotations, enforcedAllowListAnnotation)
	} else {
		if annotations == nil {
			annotations = map[string]string{}
		}

		annotations[enforcedAllowListAnnotation] = hash
	}

	spod.SetAnnotations(annotations)

	err := r.client.Patch(ctx, spod, patch)
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("recording the enforced allow lists: %w", err)
	}

	return nil
}

// notAllowed returns true if the allow lists reject the syscalls of the
// profile merged with the ones of its base profiles, like the daemon
// validates them. Profiles whose base profiles cannot be resolved here, like
// OCI artifacts, which only the daemons pull, are left to the daemons, which
// reject them without deleting them.
func (r *ReconcileSPOd) notAllowed(
	ctx context.Context,
	sp *seccompprofileapi.SeccompProfile,
	security *spodapi.SPODSecurityConfig,
) bool {
	if !sp.GetDeletionTimestamp().IsZero() {
		return false
	}

	// Seccomp profiles are cluster scoped.
	logger := r.log.WithValues("name", sp.GetName())

	syscalls, err := seccompcheck.ResolveLocalSyscalls(ctx, r.client, sp)
	if err != nil {
		logger.Info("Cannot resolve the syscalls of the seccomp profile, leaving it to the daemons",
			"error", err.Error())

		return false
	}

	merged := sp.DeepCopy()
	merged.Spec.Syscalls = syscalls

	err = seccompcheck.AllowProfile(
		merged,
		security.AllowedSyscalls,
		security.AllowedSeccompActions,
	)
	if err == nil {
		return false
	}

	logger.Info("Deleting not allowed seccomp profile", "reason", err.Error())

	return true
}

// rejectedByAllowLists returns true if the allow lists of the SPOD reject the
// profile, which has no base profile, like reconcileAllowList decides it.
func rejectedByAllowLists(
	sp *seccompprofileapi.SeccompProfile, security *spodapi.SPODSecurityConfig,
) bool {
	if len(security.AllowedSyscalls) == 0 {
		return false
	}

	if _, err := seccompcheck.CheckedActions(security.AllowedSeccompActions); err != nil {
		return false
	}

	return seccompcheck.AllowProfile(
		sp, security.AllowedSyscalls, security.AllowedSeccompActions,
	) != nil
}
