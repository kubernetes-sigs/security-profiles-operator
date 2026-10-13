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
	"slices"

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
	if maxLen-len(hashPrefix)-1 < 1 { // -1 for the dash separator
		return "", fmt.Errorf(
			"shortening string: prefix %q leaves no room for a hash within %d characters",
			hashPrefix, maxLen,
		)
	}

	return withHash(maxLen, hashPrefix, name), nil
}

// withHash returns the prefix and as much of the SHA256 hash of name as fits
// into maxLen. The prefix has to leave room for at least one character of the
// hash.
func withHash(maxLen int, hashPrefix, name string) string {
	sum := sha256.Sum256([]byte(name))
	hashStr := hex.EncodeToString(sum[:])

	return hashPrefix + "-" + hashStr[:min(maxLen-len(hashPrefix)-1, len(hashStr))]
}

// dnsMinHashLen is how many characters of the hash a hashed DNS label name
// keeps at least.
const dnsMinHashLen = 16

// DNSLengthName returns the friendly name if it fits into a DNS label, and
// its hashed form otherwise, see lengthName. A prefix too long to leave room
// for the hash gets shortened, so that the name is never empty. The callers
// pass profile kinds, which are short enough to be kept as they are.
func DNSLengthName(hashPrefix, format string, a ...any) string {
	const maxPrefixLen = validation.DNS1123LabelMaxLength - 1 - dnsMinHashLen

	friendlyName := fmt.Sprintf(format, a...)
	if len(friendlyName) < validation.DNS1123LabelMaxLength {
		return friendlyName
	}

	return withHash(
		validation.DNS1123LabelMaxLength,
		hashPrefix[:min(len(hashPrefix), maxPrefixLen)],
		friendlyName,
	)
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

// RecordsContainer returns true if the recording selects the container: an
// unset container list selects every container of the pod.
func RecordsContainer(recording *profilerecordingapi.ProfileRecording, containerName string) bool {
	return recording.Spec.Containers == nil ||
		slices.Contains(recording.Spec.Containers, containerName)
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
