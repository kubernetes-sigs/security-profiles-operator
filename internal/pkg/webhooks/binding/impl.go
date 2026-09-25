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

package binding

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

type defaultImpl struct {
	client client.Client
	reader client.Reader
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	ListProfileBindings(
		context.Context,
		...client.ListOption,
	) (*profilebindingapi.ProfileBindingList, error)
	GetSeccompProfile(
		context.Context,
		types.NamespacedName,
	) (*seccompprofileapi.SeccompProfile, error)
	GetSelinuxProfile(
		context.Context,
		types.NamespacedName,
	) (*selinuxprofileapi.SelinuxProfile, error)
	GetAppArmorProfile(
		context.Context,
		types.NamespacedName,
	) (*apparmorprofileapi.AppArmorProfile, error)
	GetSPOD(
		context.Context,
		types.NamespacedName,
	) (*spodapi.SecurityProfilesOperatorDaemon, error)
}

func (d *defaultImpl) ListProfileBindings(
	ctx context.Context, opts ...client.ListOption,
) (*profilebindingapi.ProfileBindingList, error) {
	profileBindings := &profilebindingapi.ProfileBindingList{}
	if err := d.client.List(ctx, profileBindings, opts...); err != nil {
		return nil, fmt.Errorf("list profile bindings: %w", err)
	}

	return profileBindings, nil
}

func (d *defaultImpl) GetSeccompProfile(
	ctx context.Context, key types.NamespacedName,
) (*seccompprofileapi.SeccompProfile, error) {
	seccompProfile := &seccompprofileapi.SeccompProfile{}
	if err := d.client.Get(ctx, key, seccompProfile); err != nil {
		return nil, fmt.Errorf("get seccomp profile: %w", err)
	}

	return seccompProfile, nil
}

func (d *defaultImpl) GetSelinuxProfile(
	ctx context.Context, key types.NamespacedName,
) (*selinuxprofileapi.SelinuxProfile, error) {
	selinuxProfile := &selinuxprofileapi.SelinuxProfile{}

	err := d.client.Get(ctx, key, selinuxProfile)
	if err != nil {
		return nil, fmt.Errorf("get selinux profile: %w", err)
	}

	return selinuxProfile, nil
}

func (d *defaultImpl) GetAppArmorProfile(
	ctx context.Context, key types.NamespacedName,
) (*apparmorprofileapi.AppArmorProfile, error) {
	appArmorProfile := &apparmorprofileapi.AppArmorProfile{}
	if err := d.client.Get(ctx, key, appArmorProfile); err != nil {
		return nil, fmt.Errorf("get apparmor profile: %w", err)
	}

	return appArmorProfile, nil
}

// GetSPOD reads the SPOD directly from the API server, because it is only
// needed for bindings to profiles without status.
func (d *defaultImpl) GetSPOD(
	ctx context.Context, key types.NamespacedName,
) (*spodapi.SecurityProfilesOperatorDaemon, error) {
	spod := &spodapi.SecurityProfilesOperatorDaemon{}
	if err := d.reader.Get(ctx, key, spod); err != nil {
		return nil, fmt.Errorf("get spod: %w", err)
	}

	return spod, nil
}
