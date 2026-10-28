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

package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"reflect"

	yamlv3 "go.yaml.in/yaml/v3"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// ErrMultipleDocuments is returned by CheckSingleDocument for content with
// more than one YAML document.
var ErrMultipleDocuments = errors.New(
	"the file has several YAML documents, like the output of spoc record -t all, " +
		"split it into one file per profile",
)

// CheckSingleDocument returns ErrMultipleDocuments if the content has more
// than one YAML document which is not empty. ReadProfile only reads the first
// one, the others would be dropped without a word.
func CheckSingleDocument(content []byte) error {
	decoder := yamlv3.NewDecoder(bytes.NewReader(content))
	documents := 0

	for {
		var document yamlv3.Node

		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("%w: %w", ErrDecodeYAML, err)
		}

		if emptyDocument(&document) {
			continue
		}

		documents++
		if documents > 1 {
			return ErrMultipleDocuments
		}
	}
}

// emptyDocument reports whether a YAML document has no content, like one of
// comments only, or null.
func emptyDocument(document *yamlv3.Node) bool {
	if len(document.Content) == 0 {
		return true
	}

	content := document.Content[0]

	return content.Kind == yamlv3.ScalarNode && content.Tag == "!!null"
}

// ReadSingleProfile is ReadProfile for content which has to hold a single
// profile, like a file passed to spoc.
func ReadSingleProfile(content []byte) (client.Object, error) {
	if err := CheckSingleDocument(content); err != nil {
		return nil, err
	}

	profile, err := ReadProfile(content)
	if err != nil {
		return nil, err
	}

	// A misspelled field would be dropped without a word. Profiles written
	// by newer versions may have fields this one does not know, so they are
	// only warned about.
	if err := unknownFields(content, profile); err != nil {
		log.Printf("WARNING: Ignoring what the profile has beyond the known fields: %v", err)
	}

	return profile, nil
}

// unknownFields returns the error of decoding content strictly into a new
// object of the type of profile, which tells the fields it does not know.
func unknownFields(content []byte, profile client.Object) error {
	fresh, ok := reflect.TypeAssert[client.Object](reflect.New(reflect.TypeOf(profile).Elem()))
	if !ok {
		return nil
	}

	return yaml.UnmarshalStrict(content, fresh)
}

// ReadProfile unmarshals a raw security profile YAML byte slice into a SeccompProfile, SelinuxProfile,
// or AppArmorProfile struct. The caller can then use `switch obj := profile.(type) { ... `.
func ReadProfile(content []byte) (client.Object, error) {
	// yaml.Unmarshal happily takes YAML for a SELinux profile and unmarshals
	// it into SeccompProfile. We need to check the YAML kind!
	var genericCRD map[string]any

	err := yaml.Unmarshal(content, &genericCRD)
	if err != nil {
		return nil, fmt.Errorf("cannot parse yaml: %w", err)
	}

	kind, ok := genericCRD["kind"].(string)
	if !ok {
		return nil, ErrNoKind
	}

	switch kind {
	case "SeccompProfile":
		var profile seccompprofileapi.SeccompProfile
		if err := yaml.Unmarshal(content, &profile); err != nil {
			return nil, fmt.Errorf("unmarshal to seccomp profile: %w", err)
		}

		return &profile, nil
	case "SelinuxProfile":
		var profile selinuxprofileapi.SelinuxProfile
		if err := yaml.Unmarshal(content, &profile); err != nil {
			return nil, fmt.Errorf("unmarshal to selinux profile: %w", err)
		}

		return &profile, nil
	case "AppArmorProfile":
		var profile apparmorprofileapi.AppArmorProfile
		if err := yaml.Unmarshal(content, &profile); err != nil {
			return nil, fmt.Errorf("unmarshal to apparmor profile: %w", err)
		}

		return &profile, nil
	default:
		return nil, fmt.Errorf("unexpected YAML kind: %s", kind)
	}
}
