/*
Copyright 2020 The Kubernetes Authors.

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
)

func NamespacedName(name, namespace string) types.NamespacedName {
	return types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
}

// Contains returns true if the slice a contains string b.
func Contains(a []string, b string) bool {
	for _, s := range a {
		if s == b {
			return true
		}
	}

	return false
}

// LengthName creates a string of maximum defined length.
func lengthName(maxLen int, hashPrefix, format string, a ...interface{}) (string, error) {
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

func dnsLengthName(hashPrefix, format string, a ...interface{}) string {
	//nolint:errcheck // (jhrozek): I think it makes sense to make the utility
	// 					  function return error, but here I think it's OK to
	// 					  just ignore
	name, _ := lengthName(validation.DNS1123LabelMaxLength, hashPrefix, format, a...)

	return name
}

func KindBasedDNSLengthName(obj client.Object) string {
	kind := obj.GetObjectKind().GroupVersionKind().Kind

	return dnsLengthName(kind, "%s-%s", kind, obj.GetName())
}
