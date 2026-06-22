/*
Copyright 2022 The Kubernetes Authors.

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

package recordingmerger

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

type mergeableAppArmorProfile struct {
	apparmorprofileapi.AppArmorProfile
}

func (sp *mergeableAppArmorProfile) getProfile() client.Object {
	return &sp.AppArmorProfile
}

func (sp *mergeableAppArmorProfile) merge(other mergeableProfile) error {
	otherSP, ok := other.(*mergeableAppArmorProfile)
	if !ok {
		return fmt.Errorf("cannot merge AppArmorProfile with %T", other)
	}

	merged, err := util.UnionAppArmor(&sp.Spec.Abstract, &otherSP.Spec.Abstract)
	if err != nil {
		return fmt.Errorf("merge apparmor profiles: %w", err)
	}

	sp.Spec.Abstract.Executable = merged.Executable
	sp.Spec.Abstract.Filesystem = merged.Filesystem
	sp.Spec.Abstract.Network = merged.Network
	sp.Spec.Abstract.Capability = merged.Capability

	return nil
}
