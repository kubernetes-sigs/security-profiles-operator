/*
Copyright 2025 The Kubernetes Authors.

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

package v1alpha1

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
)

func (src *SecurityProfileNodeStatus) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*secprofnodestatusv1.SecurityProfileNodeStatus)
	if !ok {
		return fmt.Errorf("expected *secprofnodestatusv1.SecurityProfileNodeStatus, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.NodeName = src.Spec.NodeName
	dst.Status.Status = secprofnodestatusv1.ProfileState(src.Status.Status)

	return nil
}

func (dst *SecurityProfileNodeStatus) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*secprofnodestatusv1.SecurityProfileNodeStatus)
	if !ok {
		return fmt.Errorf("expected *secprofnodestatusv1.SecurityProfileNodeStatus, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.NodeName = src.Spec.NodeName
	dst.Status.Status = ProfileState(src.Status.Status)

	return nil
}
