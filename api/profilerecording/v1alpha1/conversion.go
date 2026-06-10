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

	profilerecordingv1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

var (
	recorderToV1 = map[ProfileRecorder]profilerecordingv1.ProfileRecorder{
		"":                  profilerecordingv1.ProfileRecorderLogs,
		ProfileRecorderLogs: profilerecordingv1.ProfileRecorderLogs,
		ProfileRecorderBpf:  profilerecordingv1.ProfileRecorderBpf,
	}
	recorderFromV1 = map[profilerecordingv1.ProfileRecorder]ProfileRecorder{
		"":                                     ProfileRecorderLogs,
		profilerecordingv1.ProfileRecorderLogs: ProfileRecorderLogs,
		profilerecordingv1.ProfileRecorderBpf:  ProfileRecorderBpf,
	}
	mergeToV1 = map[ProfileMergeStrategy]profilerecordingv1.ProfileMergeStrategy{
		"":                     profilerecordingv1.ProfileMergeNone,
		ProfileMergeNone:       profilerecordingv1.ProfileMergeNone,
		ProfileMergeContainers: profilerecordingv1.ProfileMergeContainers,
	}
	mergeFromV1 = map[profilerecordingv1.ProfileMergeStrategy]ProfileMergeStrategy{
		"":                                  ProfileMergeNone,
		profilerecordingv1.ProfileMergeNone: ProfileMergeNone,
		profilerecordingv1.ProfileMergeContainers: ProfileMergeContainers,
	}
)

func (src *ProfileRecording) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*profilerecordingv1.ProfileRecording)
	if !ok {
		return fmt.Errorf("expected *profilerecordingv1.ProfileRecording, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.Kind = profilerecordingv1.ProfileRecordingKind(src.Spec.Kind)
	dst.Spec.Recorder = recorderToV1[src.Spec.Recorder]
	dst.Spec.MergeStrategy = mergeToV1[src.Spec.MergeStrategy]
	dst.Spec.PodSelector = src.Spec.PodSelector
	dst.Spec.Containers = src.Spec.Containers
	dst.Spec.DisableProfileAfterRecording = src.Spec.DisableProfileAfterRecording

	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}

func (dst *ProfileRecording) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*profilerecordingv1.ProfileRecording)
	if !ok {
		return fmt.Errorf("expected *profilerecordingv1.ProfileRecording, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	dst.Spec.Kind = ProfileRecordingKind(src.Spec.Kind)
	dst.Spec.Recorder = recorderFromV1[src.Spec.Recorder]
	dst.Spec.MergeStrategy = mergeFromV1[src.Spec.MergeStrategy]
	dst.Spec.PodSelector = src.Spec.PodSelector
	dst.Spec.Containers = src.Spec.Containers
	dst.Spec.DisableProfileAfterRecording = src.Spec.DisableProfileAfterRecording

	dst.Status.ActiveWorkloads = src.Status.ActiveWorkloads

	return nil
}
