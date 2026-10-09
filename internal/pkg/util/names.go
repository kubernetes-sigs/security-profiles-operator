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

package util

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

func NamespacedName(name, namespace string) types.NamespacedName {
	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

// lengthName creates a string of less than maxLen characters. A friendly name
// which fits is returned as is, a longer one is replaced by its hashed form,
// see hashedName.
//
// A friendly name of exactly maxLen characters would fit as well, but gets
// hashed too. This is an off-by-one, but the result names the node status
// objects and their labels, so changing the threshold would orphan the
// statuses of every profile whose friendly name has exactly maxLen characters.
func lengthName(maxLen int, hashPrefix, format string, a ...any) (string, error) {
	friendlyName := fmt.Sprintf(format, a...)
	if len(friendlyName) < maxLen {
		return friendlyName, nil
	}

	return hashedName(maxLen, hashPrefix, friendlyName)
}

// hashedName returns hashPrefix, a dash and as much of the hex encoded SHA-256
// hash of name as fits into maxLen characters. It is not very user friendly,
// but it keeps names apart which a truncation would merge.
func hashedName(maxLen int, hashPrefix, name string) (string, error) {
	hasher := sha256.New()
	if _, err := io.WriteString(hasher, name); err != nil {
		return "", fmt.Errorf("writing string: %w", err)
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))

	hashUseLen := maxLen - len(hashPrefix) - 1 // -1 for the dash separator
	if hashUseLen < 1 {
		return "", fmt.Errorf(
			"shortening string: prefix %q leaves no room for a hash within %d characters",
			hashPrefix, maxLen,
		)
	}

	return hashPrefix + "-" + hashStr[:min(hashUseLen, len(hashStr))], nil
}

func DNSLengthName(hashPrefix, format string, a ...any) string {
	//nolint:errcheck // (jhrozek): I think it makes sense to make the utility
	// 					  function return error, but here I think it's OK to
	// 					  just ignore
	name, _ := lengthName(validation.DNS1123LabelMaxLength, hashPrefix, format, a...)

	return name
}

// ErrProfileOwnedByOtherRecording is returned by CheckRecordingOwner if a
// profile got recorded by another profile recording or was not recorded at
// all.
var ErrProfileOwnedByOtherRecording = errors.New("profile belongs to another profile recording")

// CheckRecordingOwner verifies that an existing profile was recorded by the
// recording with the provided name and namespace. Recorded profiles are
// cluster scoped and named after the recording, so recordings with the same
// name in different namespaces would otherwise overwrite each other's profiles.
// Objects which do not exist yet pass the check. Existing objects without the
// recording label were not recorded and are treated as foreign, because a
// recording must never replace a profile written by somebody else.
func CheckRecordingOwner(profile client.Object, recordingName, recordingNamespace string) error {
	if profile.GetResourceVersion() == "" {
		return nil
	}

	labels := profile.GetLabels()

	name, hasName := labels[profilerecordingapi.ProfileToRecordingLabel]
	namespace, hasNamespace := labels[profilerecordingapi.ProfileToRecordingNamespaceLabel]

	if !hasName {
		return fmt.Errorf(
			"%w: profile %s was not recorded, refusing to overwrite it by %s/%s",
			ErrProfileOwnedByOtherRecording, profile.GetName(),
			recordingNamespace, recordingName,
		)
	}

	// Profiles recorded before the namespace label existed only carry the
	// recording name. The manager labels them with the namespace of their
	// recording at startup where it can tell it, see the recording merger.
	// The others are accepted, like before the label existed, and the writer
	// adds the label, so that only its namespace can write them afterwards.
	if name != recordingName || (hasNamespace && namespace != recordingNamespace) {
		return fmt.Errorf(
			"%w: profile %s was recorded by %s/%s, not by %s/%s",
			ErrProfileOwnedByOtherRecording, profile.GetName(),
			namespace, name, recordingNamespace, recordingName,
		)
	}

	return nil
}

// IsLegacyRecordedProfile returns true if the profile was recorded before the
// recording namespace label existed: it carries the recording name, but not
// the namespace of the recording.
func IsLegacyRecordedProfile(profile client.Object) bool {
	labels := profile.GetLabels()
	_, hasName := labels[profilerecordingapi.ProfileToRecordingLabel]
	_, hasNamespace := labels[profilerecordingapi.ProfileToRecordingNamespaceLabel]

	return hasName && !hasNamespace
}

// RecordedProfileName returns the name of the profile which a recording
// records for a container. The suffix tells the replicas apart, it is empty
// for a merged profile and for a pod without generated name.
func RecordedProfileName(recordingName, containerName, suffix string) string {
	name := recordingName + "-" + containerName
	if suffix != "" {
		name += "-" + suffix
	}

	return name
}

// nodeLabelHashPrefixLen is how many characters of a long node name are kept
// in front of its hash in a label value, so that the value still hints at the
// node.
const nodeLabelHashPrefixLen = 16

// NodeNameLabelValue returns a label value which identifies the node. Node
// names may be longer than a label value, those get shortened by hashing
// them. Shorter node names are returned as is, so that existing label values
// do not change.
func NodeNameLabelValue(nodeName string) string {
	if len(nodeName) <= validation.LabelValueMaxLength {
		return nodeName
	}

	hashed, err := hashedName(
		validation.LabelValueMaxLength, nodeName[:nodeLabelHashPrefixLen], nodeName,
	)
	if err != nil {
		// Cannot happen: the prefix leaves room for the hash.
		return nodeName[:validation.LabelValueMaxLength]
	}

	return hashed
}

// KindNameDNSLengthName returns the label value which identifies the profile
// of the kind and name. It takes the kind explicitly, because the TypeMeta of
// objects may have been cleared.
func KindNameDNSLengthName(kind, name string) string {
	return DNSLengthName(kind, "%s-%s", kind, name)
}
