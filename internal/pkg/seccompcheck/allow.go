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

// Package seccompcheck contains the checks of seccomp profiles against the allow
// lists of the SPOD, which the daemon and the manager share.
package seccompcheck

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// MaxBaseProfileDepth is the maximum depth of a chain of base profiles.
const MaxBaseProfileDepth = 15

var (
	// ErrForbiddenSyscall is returned if a profile uses a syscall which the
	// SPOD does not allow.
	ErrForbiddenSyscall = errors.New("syscall not allowed")
	// ErrForbiddenProfile is returned if the default action of a profile is
	// one of the checked actions, which would allow every syscall.
	ErrForbiddenProfile = errors.New("seccomp profile not allowed")
	// ErrForbiddenAction is returned if the allowed actions of the SPOD
	// contain an action whose syscalls cannot be checked.
	ErrForbiddenAction = errors.New("seccomp action not allowed")
	// ErrOCIBaseProfile is returned by ResolveLocalSyscalls if a profile in
	// the chain of base profiles is an OCI artifact.
	ErrOCIBaseProfile = errors.New("base profile is an OCI artifact")
	// ErrInvalidBaseProfile is returned by ResolveLocalSyscalls if the chain
	// of base profiles cannot be resolved.
	ErrInvalidBaseProfile = errors.New("invalid base profile")
)

// NotAllowed returns true if err is a rejection of a profile by the SPOD
// configuration, which retrying cannot change.
func NotAllowed(err error) bool {
	return errors.Is(err, ErrForbiddenSyscall) ||
		errors.Is(err, ErrForbiddenProfile) ||
		errors.Is(err, ErrForbiddenAction)
}

// checkableActions are the actions whose syscalls can be checked against the
// allowed syscalls of the SPOD.
var checkableActions = []seccompprofileapi.Action{
	seccompprofileapi.ActAllow,
	seccompprofileapi.ActLog,
	seccompprofileapi.ActTrace,
	seccompprofileapi.ActNotify,
}

// CheckedActions returns the actions whose syscalls get checked for the
// allowedSeccompActions of the SPOD. It fails if they contain an action which
// cannot be checked.
func CheckedActions(
	allowedActions []seccompprofileapi.Action,
) ([]seccompprofileapi.Action, error) {
	if len(allowedActions) == 0 {
		return checkableActions, nil
	}

	for _, allowedAction := range allowedActions {
		if !slices.Contains(checkableActions, allowedAction) {
			return nil, fmt.Errorf("%w: %s", ErrForbiddenAction, allowedAction)
		}
	}

	return allowedActions, nil
}

// AllowProfile checks the syscalls of the profile against the allowed
// syscalls and actions of the SPOD. An empty list of allowed syscalls means
// that the SPOD does not restrict them, so every profile passes.
func AllowProfile(
	profile *seccompprofileapi.SeccompProfile,
	allowedSyscalls []string,
	allowedActions []seccompprofileapi.Action,
) error {
	if len(allowedSyscalls) == 0 {
		return nil
	}

	syscalls := map[seccompprofileapi.Action]map[string]bool{}
	for _, call := range profile.Spec.Syscalls {
		if _, ok := syscalls[call.Action]; !ok {
			syscalls[call.Action] = map[string]bool{}
		}

		for _, name := range call.Names {
			syscalls[call.Action][name] = true
		}
	}

	allowedActions, err := CheckedActions(allowedActions)
	if err != nil {
		return err
	}

	// Hoisted out of the loop: a linear scan per syscall makes this O(n*m),
	// and the manager runs it over every profile in the cluster whenever the
	// allow lists of the SPOD change.
	allowed := sets.New(allowedSyscalls...)

	for _, action := range allowedActions {
		if actionCalls, ok := syscalls[action]; ok {
			for call := range actionCalls {
				if !allowed.Has(call) {
					return fmt.Errorf("%w: %s", ErrForbiddenSyscall, call)
				}
			}
		}

		if profile.Spec.DefaultAction == action {
			return ErrForbiddenProfile
		}
	}

	return nil
}

// ResolveLocalSyscalls returns the syscalls of the profile merged with the
// ones of its base profiles, which have to be SeccompProfiles in the
// namespace of the profile. It fails with ErrOCIBaseProfile if the chain
// contains an OCI artifact, which only the daemon on the node pulls.
func ResolveLocalSyscalls(
	ctx context.Context,
	c client.Reader,
	sp *seccompprofileapi.SeccompProfile,
) ([]seccompprofileapi.Syscall, error) {
	syscalls := sp.Spec.Syscalls
	current := sp

	for range MaxBaseProfileDepth {
		baseProfileName := current.Spec.BaseProfileName
		if baseProfileName == "" {
			return syscalls, nil
		}

		if strings.HasPrefix(baseProfileName, config.OCIProfilePrefix) {
			return nil, fmt.Errorf("%w: %s", ErrOCIBaseProfile, baseProfileName)
		}

		base := &seccompprofileapi.SeccompProfile{}
		if err := c.Get(
			ctx, util.NamespacedName(baseProfileName, sp.GetNamespace()), base,
		); err != nil {
			return nil, fmt.Errorf("getting base profile %s: %w", baseProfileName, err)
		}

		merged, err := util.UnionSyscalls(base.Spec.Syscalls, syscalls)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: merging syscalls of %s: %w", ErrInvalidBaseProfile, baseProfileName, err,
			)
		}

		syscalls = merged
		current = base
	}

	return nil, fmt.Errorf(
		"%w: max recursion level of %d is reached for resolving base profiles",
		ErrInvalidBaseProfile, MaxBaseProfileDepth,
	)
}

// AllowListChangedPredicate passes the updates of a SPOD which change its
// allowedSyscalls or allowedSeccompActions. Creations, deletions and generic
// events pass as well.
type AllowListChangedPredicate struct {
	predicate.Funcs
}

// Update implements the update event filter checking whether the
// allowedSyscalls or the allowedSeccompActions of the SPOD changed.
func (AllowListChangedPredicate) Update(e event.UpdateEvent) bool {
	if e.ObjectOld == nil || e.ObjectNew == nil {
		return false
	}

	oldSpod, ok := e.ObjectOld.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	newSpod, ok := e.ObjectNew.(*spodapi.SecurityProfilesOperatorDaemon)
	if !ok {
		return false
	}

	return AllowListChanged(&oldSpod.Spec.Security, &newSpod.Spec.Security)
}

// AllowListChanged returns true if the allowed syscalls or the allowed seccomp
// actions differ between the two configurations. The order of the entries
// does not matter.
func AllowListChanged(oldCfg, newCfg *spodapi.SPODSecurityConfig) bool {
	if !sets.New(newCfg.AllowedSeccompActions...).Equal(
		sets.New(oldCfg.AllowedSeccompActions...),
	) {
		return true
	}

	if len(newCfg.AllowedSyscalls) != len(oldCfg.AllowedSyscalls) {
		return true
	}

	diff := make(map[string]int, len(newCfg.AllowedSyscalls))
	for _, s := range newCfg.AllowedSyscalls {
		diff[s]++
	}

	for _, s := range oldCfg.AllowedSyscalls {
		if _, ok := diff[s]; !ok {
			return true
		}

		diff[s]--
		if diff[s] == 0 {
			delete(diff, s)
		}
	}

	return len(diff) != 0
}
