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

	profilebindingv1 "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
)

func (src *ProfileBinding) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*profilebindingv1.ProfileBinding)
	if !ok {
		return fmt.Errorf("expected *profilebindingv1.ProfileBinding, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.ProfileRef.Kind = profilebindingv1.ProfileBindingKind(src.Spec.ProfileRef.Kind)
	dst.Spec.ProfileRef.Name = src.Spec.ProfileRef.Name
	dst.Spec.Image = src.Spec.Image

	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

func (dst *ProfileBinding) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*profilebindingv1.ProfileBinding)
	if !ok {
		return fmt.Errorf("expected *profilebindingv1.ProfileBinding, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.ProfileRef.Kind = ProfileBindingKind(src.Spec.ProfileRef.Kind)
	dst.Spec.ProfileRef.Name = src.Spec.ProfileRef.Name
	dst.Spec.Image = src.Spec.Image

	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}
