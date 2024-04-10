/*
Copyright 2024 The Kubernetes Authors.

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
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
)

// Unmarshal a raw security profile YAML byte slice into a SeccompProfile, SelinuxProfile,
// or AppArmorProfile struct. The caller can then use `switch obj := profile.(type) { ... `.
func ReadProfile(content []byte) (client.Object, error) {
	// yaml.Unmarshal happily takes YAML for a SELinux profile and unmarshals
	// it into SeccompProfile. We need to check the YAML kind!
	var genericCRD map[string]interface{}
	err := yaml.Unmarshal(content, &genericCRD)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("cannot parse yaml: %w", err)
	}
	kind, ok := genericCRD["kind"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid yaml, kind missing: %w", err)
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
