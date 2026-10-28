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
	"context"
	"fmt"
	"sync"

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

// RecordingNames returns the names which a recording that recorded the
// profile may have: the recorded profiles are named after the recording,
// followed by a dash and the container, see util.RecordedProfileName. A
// recording name ends in front of any of the dashes of the profile name.
func RecordingNames(profileName string) []string {
	var names []string

	for i := range len(profileName) {
		if profileName[i] == '-' && i > 0 {
			names = append(names, profileName[:i])
		}
	}

	return names
}

// RecordingNameKey indexes the recordings by their name, see
// IndexRecordingNames. The API server supports it as field selector as well.
const RecordingNameKey = "metadata.name"

// RecordingNameIndex indexes the recordings by their name.
func RecordingNameIndex(obj client.Object) []string {
	return []string{obj.GetName()}
}

var (
	recordingNamesIndexedMu sync.Mutex
	// recordingNamesIndexed holds the indexers which have the
	// RecordingNameKey index, the caches of the managers are pointers.
	recordingNamesIndexed = map[client.FieldIndexer]bool{}
)

// IndexRecordingNames adds the RecordingNameKey index of the recordings to
// the indexer, unless it has it already. The recording merger and the
// recording tracker both use it and can be enabled independently, while an
// informer rejects an index which it has already. That error has no type to
// tell it apart, and the informers of a cache restricted to namespaces do not
// expose their indexers, so the indexers which got the index are recorded.
func IndexRecordingNames(ctx context.Context, indexer client.FieldIndexer) error {
	recordingNamesIndexedMu.Lock()
	defer recordingNamesIndexedMu.Unlock()

	if recordingNamesIndexed[indexer] {
		return nil
	}

	if err := indexer.IndexField(
		ctx, &profilerecordingapi.ProfileRecording{}, RecordingNameKey, RecordingNameIndex,
	); err != nil {
		return fmt.Errorf("creating profile recording name index: %w", err)
	}

	recordingNamesIndexed[indexer] = true

	return nil
}
