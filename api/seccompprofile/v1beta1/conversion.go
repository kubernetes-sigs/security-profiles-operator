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

package v1beta1

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	profilebasev1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	seccompprofilev1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusv1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
)

func (src *SeccompProfile) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*seccompprofilev1.SeccompProfile)
	if !ok {
		return fmt.Errorf("expected *seccompprofilev1.SeccompProfile, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.State = profilebasev1.SpecState(src.Spec.State)
	dst.Spec.BaseProfileName = src.Spec.BaseProfileName
	dst.Spec.DefaultAction = src.Spec.DefaultAction
	dst.Spec.ListenerPath = src.Spec.ListenerPath
	dst.Spec.ListenerMetadata = src.Spec.ListenerMetadata

	dst.Spec.Architectures = make([]seccompprofilev1.Arch, len(src.Spec.Architectures))
	for i, a := range src.Spec.Architectures {
		dst.Spec.Architectures[i] = seccompprofilev1.Arch(a)
	}

	dst.Spec.Syscalls = make([]seccompprofilev1.Syscall, len(src.Spec.Syscalls))
	for i, s := range src.Spec.Syscalls {
		dst.Spec.Syscalls[i] = seccompprofilev1.Syscall{
			Names:    s.Names,
			Action:   s.Action,
			ErrnoRet: s.ErrnoRet,
		}

		dst.Spec.Syscalls[i].Args = make([]seccompprofilev1.Arg, len(s.Args))

		for j, a := range s.Args {
			arg := seccompprofilev1.Arg{
				Value:    a.Value,
				ValueTwo: a.ValueTwo,
				Op:       a.Op,
			}

			if a.Index != nil {
				idx := *a.Index
				arg.Index = &idx
			}

			dst.Spec.Syscalls[i].Args[j] = arg
		}
	}

	dst.Spec.Flags = make([]seccompprofilev1.Flag, len(src.Spec.Flags))
	for i, f := range src.Spec.Flags {
		dst.Spec.Flags[i] = seccompprofilev1.Flag(f)
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1.ProfileState(src.Status.Status)
	dst.Status.Path = src.Status.Path
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads
	dst.Status.LocalhostProfile = src.Status.LocalhostProfile

	return nil
}

func (dst *SeccompProfile) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*seccompprofilev1.SeccompProfile)
	if !ok {
		return fmt.Errorf("expected *seccompprofilev1.SeccompProfile, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.State = profilebasev1alpha1.SpecState(src.Spec.State)
	dst.Spec.BaseProfileName = src.Spec.BaseProfileName
	dst.Spec.DefaultAction = src.Spec.DefaultAction
	dst.Spec.ListenerPath = src.Spec.ListenerPath
	dst.Spec.ListenerMetadata = src.Spec.ListenerMetadata

	dst.Spec.Architectures = make([]Arch, len(src.Spec.Architectures))
	for i, a := range src.Spec.Architectures {
		dst.Spec.Architectures[i] = Arch(a)
	}

	dst.Spec.Syscalls = make([]Syscall, len(src.Spec.Syscalls))
	for i, s := range src.Spec.Syscalls {
		dst.Spec.Syscalls[i] = Syscall{
			Names:    s.Names,
			Action:   s.Action,
			ErrnoRet: s.ErrnoRet,
		}

		dst.Spec.Syscalls[i].Args = make([]Arg, len(s.Args))

		for j, a := range s.Args {
			arg := Arg{
				Value:    a.Value,
				ValueTwo: a.ValueTwo,
				Op:       a.Op,
			}

			if a.Index != nil {
				idx := *a.Index
				arg.Index = &idx
			}

			dst.Spec.Syscalls[i].Args[j] = arg
		}
	}

	dst.Spec.Flags = make([]Flag, len(src.Spec.Flags))
	for i, f := range src.Spec.Flags {
		dst.Spec.Flags[i] = Flag(f)
	}

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.Status = secprofnodestatusv1alpha1.ProfileState(src.Status.Status)
	dst.Status.Path = src.Status.Path
	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads
	dst.Status.LocalhostProfile = src.Status.LocalhostProfile

	return nil
}
