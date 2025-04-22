/*
Copyright 2020 The Kubernetes Authors.

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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	selxv1alpha2 "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
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
		For(&selxv1alpha2.SelinuxProfile{}).
		WithEventFilter(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.LabelChangedPredicate{})).
		Complete(r)
}

var _ SelinuxObjectHandler = &selinuxProfileHandler{}

type selinuxProfileHandler struct {
	sp                *selxv1alpha2.SelinuxProfile
	cli               client.Client
	systemInherits    []string
	objInherits       []selxv1alpha2.SelinuxProfileObject
	labelRegex        *regexp.Regexp
	objClassPermRegex *regexp.Regexp
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
		return err
	}

	// Matches alpha numerical names in upper and lower-case, as well as
	// dashes and underscores. @self is also allowed explicitly.
	// Must be at least one character.
	// The characters must match from beginning to end of the string
	sph.labelRegex = regexp.MustCompile(`^([a-zA-Z0-9.\-_]+|@self)$`)

	// Matches alpha numerical names in upper and lower-case, as well as
	// dashes and underscores.
	// Must be at least one character.
	// The characters must match from beginning to end of the string
	sph.objClassPermRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-_]+$`)

	return nil
}

func (sph *selinuxProfileHandler) GetProfileObject() selxv1alpha2.SelinuxProfileObject {
	return sph.sp
}

func (sph *selinuxProfileHandler) Validate() error {
	for _, inherit := range sph.sp.Spec.Inherit {
		err := sph.validateAndTrackInherit(inherit, sph.sp.GetNamespace())
		if err != nil {
			return err
		}
	}

	for key, classperms := range sph.sp.Spec.Allow {
		if err := sph.validateLabelKey(key); err != nil {
			return err
		}

		for objclass, perms := range classperms {
			if err := sph.validateObjClass(objclass); err != nil {
				return err
			}

			for _, perm := range perms {
				if err := sph.validatePermission(perm); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (sph *selinuxProfileHandler) validateAndTrackInherit(
	ancestorRef selxv1alpha2.PolicyRef,
	namespace string,
) error {
	switch ancestorRef.Kind {
	// We default to System if Kind is left empty
	case selxv1alpha2.SystemPolicyKind, "":
		return sph.handleInheritSystemPolicy(ancestorRef)
	case "SelinuxProfile":
		return sph.handleInheritSPOPolicy(ancestorRef, namespace)
	}

	return fmt.Errorf("%s/%s: %w", ancestorRef.Kind, ancestorRef.Name, ErrUnknownKindForEntry)
}

func (sph *selinuxProfileHandler) validateLabelKey(
	key selxv1alpha2.LabelKey,
) error {
	if !sph.labelRegex.MatchString(string(key)) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", key, ErrInvalidLabelKey)
	}

	return nil
}

func (sph *selinuxProfileHandler) validateObjClass(
	key selxv1alpha2.ObjectClassKey,
) error {
	if !sph.objClassPermRegex.MatchString(string(key)) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", key, ErrInvalidObjClass)
	}

	return nil
}

func (sph *selinuxProfileHandler) validatePermission(
	perm string,
) error {
	if !sph.objClassPermRegex.MatchString(perm) {
		return fmt.Errorf("'%s' didn't match expected characters: %w", perm, ErrInvalidPermission)
	}

	return nil
}

func (sph *selinuxProfileHandler) handleInheritSPOPolicy(
	ancestorRef selxv1alpha2.PolicyRef,
	namespace string,
) error {
	ancestor := &selxv1alpha2.SelinuxProfile{}
	key := types.NamespacedName{Name: ancestorRef.Name, Namespace: namespace}

	err := sph.cli.Get(context.Background(), key, ancestor)
	if err != nil && kerrors.IsNotFound(err) {
		return fmt.Errorf("couldn't find inherit reference %s/%s: %w",
			ancestorRef.Kind, ancestorRef.Name, err)
	}

	// TODO(jaosorior): Handle dependencies... we could force a waiting period
	// until the ancestor policy would be installed
	sph.objInherits = append(sph.objInherits, ancestor)

	return nil
}

func (sph *selinuxProfileHandler) handleInheritSystemPolicy(
	ancestorRef selxv1alpha2.PolicyRef,
) error {
	spod, err := common.GetSPOD(context.Background(), sph.cli)
	if err != nil {
		return fmt.Errorf("couldn't get spod to verify system inheritance: %w", err)
	}

	for idx := range spod.Spec.SelinuxOpts.AllowedSystemProfiles {
		prof := spod.Spec.SelinuxOpts.AllowedSystemProfiles[idx]
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
	// have been initialized already
	// At this point, validation has happened and no errors will happen when
	// rendering
	return translator.Object2CIL(sph.systemInherits, sph.objInherits, sph.sp), nil
}

func newSelinuxProfileHandler(
	ctx context.Context,
	cli client.Client,
	key types.NamespacedName,
) (SelinuxObjectHandler, error) {
	oh := &selinuxProfileHandler{
		sp:             &selxv1alpha2.SelinuxProfile{},
		systemInherits: make([]string, 0),
		objInherits:    make([]selxv1alpha2.SelinuxProfileObject, 0),
	}

	err := oh.Init(ctx, cli, key)

	return oh, err
}
