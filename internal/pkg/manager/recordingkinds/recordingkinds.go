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

// Package recordingkinds lists the kinds of profiles which a ProfileRecording
// records, for the controllers which handle the recorded profiles.
package recordingkinds

import (
	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// Kind is a kind of profiles which a recording records.
type Kind struct {
	// Kind is the kind of the recording.
	Kind profilerecordingapi.ProfileRecordingKind
	// NewObject returns an empty profile of the kind.
	NewObject func() client.Object
	// NewList returns an empty list of profiles of the kind.
	NewList func() client.ObjectList
}

// All are the kinds of profiles which a recording records.
var All = []Kind{
	{
		Kind:      profilerecordingapi.ProfileRecordingKindSeccompProfile,
		NewObject: func() client.Object { return &seccompprofileapi.SeccompProfile{} },
		NewList:   func() client.ObjectList { return &seccompprofileapi.SeccompProfileList{} },
	},
	{
		Kind:      profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		NewObject: func() client.Object { return &selinuxprofileapi.SelinuxProfile{} },
		NewList:   func() client.ObjectList { return &selinuxprofileapi.SelinuxProfileList{} },
	},
	{
		Kind:      profilerecordingapi.ProfileRecordingKindAppArmorProfile,
		NewObject: func() client.Object { return &apparmorprofileapi.AppArmorProfile{} },
		NewList:   func() client.ObjectList { return &apparmorprofileapi.AppArmorProfileList{} },
	},
}

// Of returns the kind of profiles which the recording kind records, and false
// if no profiles of the kind can be recorded.
func Of(kind profilerecordingapi.ProfileRecordingKind) (Kind, bool) {
	for _, k := range All {
		if k.Kind == kind {
			return k, true
		}
	}

	return Kind{}, false
}
