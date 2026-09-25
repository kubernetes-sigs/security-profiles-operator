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

// LengthName creates a string of maximum defined length.
func lengthName(maxLen int, hashPrefix, format string, a ...any) (string, error) {
	friendlyName := fmt.Sprintf(format, a...)
	if len(friendlyName) < maxLen {
		return friendlyName, nil
	}

	// If that's too long, just hash the name. It's not very user friendly, but whatever
	hasher := sha256.New()
	if _, err := io.WriteString(hasher, friendlyName); err != nil {
		return "", fmt.Errorf("writing string: %w", err)
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))
	hashUseLen := maxLen - len(hashPrefix) - 1 // -1 for the dash separator

	if hashUseLen < maxLen {
		hashStr = hashStr[:hashUseLen]
	}

	hashedName := fmt.Sprintf("%s-%s", hashPrefix, hashStr)

	if len(hashedName) > maxLen {
		return "", errors.New("shortening string")
	}

	return hashedName, nil
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
	// recording name.
	if name != recordingName || (hasNamespace && namespace != recordingNamespace) {
		return fmt.Errorf(
			"%w: profile %s was recorded by %s/%s, not by %s/%s",
			ErrProfileOwnedByOtherRecording, profile.GetName(),
			namespace, name, recordingNamespace, recordingName,
		)
	}

	return nil
}

func KindBasedDNSLengthName(obj client.Object) string {
	return KindNameDNSLengthName(obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName())
}

// KindNameDNSLengthName is like KindBasedDNSLengthName but takes the kind
// explicitly, for objects whose TypeMeta may have been cleared.
func KindNameDNSLengthName(kind, name string) string {
	return DNSLengthName(kind, "%s-%s", kind, name)
}
