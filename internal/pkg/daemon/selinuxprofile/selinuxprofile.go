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

package selinuxprofile

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/common"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/translator"
)

var (
	ErrInvalidLabelKey         = errors.New("invalid label key")
	ErrInvalidObjClass         = errors.New("invalid object class")
	ErrInvalidPermission       = errors.New("invalid permission")
	ErrSystemInheritNotAllowed = errors.New("system profile not allowed")
	ErrUnknownKindForEntry     = errors.New("unknown inherit kind for entry")
	ErrInheritNotFound         = errors.New("inherited profile not found")
	ErrInheritCycle            = errors.New("inherited profiles form a cycle")
	ErrInheritTooDeep          = errors.New("inheritance too deep")

	// errTemporaryValidation marks validation failures which are caused by
	// the API server and not by the profile, so they have to be retried.
	errTemporaryValidation = errors.New("temporary validation failure")

	labelRegex        = regexp.MustCompile(`^([a-zA-Z0-9.\-_]+|@self)$`)
	objClassPermRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-_]+$`)
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &ReconcileSelinux{
		controllerName:    "selinuxprofile",
		objectHandlerInit: newSelinuxProfileHandler,
		ctrlBuilder:       selinuxProfileControllerBuild,
	}
}

func selinuxProfileControllerBuild(b *ctrl.Builder, r reconcile.Reconciler) error {
	return b.Named("selinuxprofile").
		For(&selinuxprofileapi.SelinuxProfile{}, builder.WithPredicates(
			predicate.GenerationChangedPredicate{},
		)).
		Complete(r)
}

var _ SelinuxObjectHandler = &selinuxProfileHandler{}

type selinuxProfileHandler struct {
	sp             *selinuxprofileapi.SelinuxProfile
	cli            client.Client
	systemInherits []string
	objInherits    []selinuxprofileapi.SelinuxProfileObject
	translatorOpts *translator.Options
}

func (sph *selinuxProfileHandler) Init(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) error {
	// init cli if not set already
	if sph.cli == nil {
		sph.cli = cli
	}
	// initiate the SelinuxProfile object
	if err := sph.cli.Get(ctx, key, sph.sp); err != nil {
		return fmt.Errorf("getting selinux profile: %w", err)
	}

	return nil
}

func (sph *selinuxProfileHandler) GetProfileObject() selinuxprofileapi.SelinuxProfileObject {
	return sph.sp
}

func (sph *selinuxProfileHandler) Validate(ctx context.Context) error {
	spod, err := common.GetSPOD(ctx, sph.cli)
	if err != nil {
		return fmt.Errorf("%w: couldn't get spod configuration: %w", errTemporaryValidation, err)
	}

	sph.handleSelinuxOptions(spod)

	for _, inherit := range sph.sp.Spec.Inherit {
		err := sph.validateAndTrackInherit(ctx, spod, inherit, sph.sp.GetNamespace())
		if err != nil {
			return fmt.Errorf("validating inherit: %w", err)
		}
	}

	for key, classperms := range sph.sp.Spec.Allow {
		if err := sph.validateLabelKey(key); err != nil {
			return fmt.Errorf("validating label key: %w", err)
		}

		for objclass, perms := range classperms {
			if err := sph.validateObjClass(objclass); err != nil {
				return fmt.Errorf("validating object class: %w", err)
			}

			for _, perm := range perms {
				if err := sph.validatePermission(perm); err != nil {
					return fmt.Errorf("validating permission: %w", err)
				}
			}
		}
	}

	return nil
}

func (sph *selinuxProfileHandler) validateAndTrackInherit(
	ctx context.Context,
	spod *spodapi.SecurityProfilesOperatorDaemon,
	ancestorRef selinuxprofileapi.PolicyRef,
	namespace string,
) error {
	switch ancestorRef.Kind {
	// We default to System if Kind is left empty
	case selinuxprofileapi.SystemPolicyKind, selinuxprofileapi.PolicyRefKind(""):
		return sph.handleInheritSystemPolicy(spod, ancestorRef)
	case selinuxprofileapi.SelinuxProfilePolicyKind:
		return sph.handleInheritSPOPolicy(ctx, ancestorRef, namespace)
	}

	return fmt.Errorf("%s/%s: %w", ancestorRef.Kind, ancestorRef.Name, ErrUnknownKindForEntry)
}

func (sph *selinuxProfileHandler) validateLabelKey(
	key selinuxprofileapi.LabelKey,
) error {
	if !labelRegex.MatchString(string(key)) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", key, ErrInvalidLabelKey)
	}

	return nil
}

func (sph *selinuxProfileHandler) validateObjClass(
	key selinuxprofileapi.ObjectClassKey,
) error {
	if !objClassPermRegex.MatchString(string(key)) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", key, ErrInvalidObjClass)
	}

	return nil
}

func (sph *selinuxProfileHandler) validatePermission(
	perm string,
) error {
	if !objClassPermRegex.MatchString(perm) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", perm, ErrInvalidPermission)
	}

	return nil
}

func (sph *selinuxProfileHandler) handleInheritSPOPolicy(
	ctx context.Context,
	ancestorRef selinuxprofileapi.PolicyRef,
	namespace string,
) error {
	ancestor := &selinuxprofileapi.SelinuxProfile{}
	key := types.NamespacedName{Name: ancestorRef.Name, Namespace: namespace}

	if err := sph.cli.Get(ctx, key, ancestor); err != nil {
		if kerrors.IsNotFound(err) {
			return fmt.Errorf("couldn't find inherit reference %s/%s: %w",
				ancestorRef.Kind, ancestorRef.Name, ErrInheritNotFound)
		}

		return fmt.Errorf("%w: getting inherit reference %s/%s: %w",
			errTemporaryValidation, ancestorRef.Kind, ancestorRef.Name, err)
	}

	if err := sph.checkInheritCycle(ctx, ancestor, namespace); err != nil {
		return err
	}

	// The reconciler waits until the ancestor is installed on the node
	// before installing this policy, see inheritedProfilesInstalled.
	sph.objInherits = append(sph.objInherits, ancestor)

	return nil
}

// maxInheritDepth limits the length of a chain of inherited profiles.
const maxInheritDepth = 32

// inheritEntry is a profile in the chain of inherited profiles, together with
// its distance from the profile which gets checked.
type inheritEntry struct {
	profile *selinuxprofileapi.SelinuxProfile
	depth   int
}

// checkInheritCycle returns an error if the profile inherits from itself,
// directly or through the profiles it inherits from, or if the chain of
// inherited profiles is too deep. Such a profile could never be installed,
// because each profile waits for its ancestors.
func (sph *selinuxProfileHandler) checkInheritCycle(
	ctx context.Context, ancestor *selinuxprofileapi.SelinuxProfile, namespace string,
) error {
	visited := map[string]bool{}
	queue := []inheritEntry{{profile: ancestor, depth: 1}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current.profile.GetName() == sph.sp.GetName() {
			return fmt.Errorf("%w: %s inherits from itself", ErrInheritCycle, sph.sp.GetName())
		}

		if current.depth > maxInheritDepth {
			return fmt.Errorf(
				"%w: more than %d levels", ErrInheritTooDeep, maxInheritDepth,
			)
		}

		if visited[current.profile.GetName()] {
			continue
		}

		visited[current.profile.GetName()] = true

		for _, ref := range current.profile.Spec.Inherit {
			if ref.Kind != selinuxprofileapi.SelinuxProfilePolicyKind {
				continue
			}

			if ref.Name == sph.sp.GetName() {
				return fmt.Errorf("%w: %s inherits from itself", ErrInheritCycle, sph.sp.GetName())
			}

			next := &selinuxprofileapi.SelinuxProfile{}

			err := sph.cli.Get(
				ctx,
				types.NamespacedName{Name: ref.Name, Namespace: namespace},
				next,
			)
			if kerrors.IsNotFound(err) {
				// The reconcile of the ancestor reports the missing profile.
				continue
			}

			if err != nil {
				return fmt.Errorf("%w: getting inherit reference %s: %w",
					errTemporaryValidation, ref.Name, err)
			}

			queue = append(queue, inheritEntry{profile: next, depth: current.depth + 1})
		}
	}

	return nil
}

// inheritedProfiles returns the profiles of the operator which the policy
// inherits from. It is only valid after Validate.
func (sph *selinuxProfileHandler) inheritedProfiles() []selinuxprofileapi.SelinuxProfileObject {
	return sph.objInherits
}

func (sph *selinuxProfileHandler) handleSelinuxOptions(
	spod *spodapi.SecurityProfilesOperatorDaemon,
) {
	sph.translatorOpts = &translator.Options{
		DeniedTypes:        spod.Spec.Selinux.Options.DeniedTypes,
		DeniedClasses:      spod.Spec.Selinux.Options.DeniedClasses,
		DeniedPermissions:  spod.Spec.Selinux.Options.DeniedPermissions,
		AllowedTypes:       spod.Spec.Selinux.Options.AllowedTypes,
		AllowedClasses:     spod.Spec.Selinux.Options.AllowedClasses,
		AllowedPermissions: spod.Spec.Selinux.Options.AllowedPermissions,
	}
}

func (sph *selinuxProfileHandler) handleInheritSystemPolicy(
	spod *spodapi.SecurityProfilesOperatorDaemon, ancestorRef selinuxprofileapi.PolicyRef,
) error {
	for idx := range spod.Spec.Selinux.Options.AllowedSystemProfiles {
		prof := spod.Spec.Selinux.Options.AllowedSystemProfiles[idx]
		if prof == ancestorRef.Name {
			sph.systemInherits = append(sph.systemInherits, ancestorRef.Name)

			return nil
		}
	}

	return fmt.Errorf(
		"system profile %s not in SecurityProfilesOperatorDaemon's allow list: %w",
		ancestorRef.Name, ErrSystemInheritNotAllowed,
	)
}

func (sph *selinuxProfileHandler) GetCILPolicy() (string, error) {
	// Note that this assumes that the client and the object
	// have been initialized already.
	return translator.Object2CIL(sph.systemInherits, sph.objInherits, sph.sp, sph.translatorOpts)
}

func newSelinuxProfileHandler(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) (SelinuxObjectHandler, error) {
	oh := &selinuxProfileHandler{
		sp:             &selinuxprofileapi.SelinuxProfile{},
		systemInherits: make([]string, 0),
		objInherits:    make([]selinuxprofileapi.SelinuxProfileObject, 0),
	}

	err := oh.Init(ctx, cli, key)

	return oh, err
}
