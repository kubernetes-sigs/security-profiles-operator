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
	"encoding/json"
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"sigs.k8s.io/security-profiles-merger/seccomp"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
)

// runtimeSpecSeccompProfile reports whether content is a raw OCI runtime-spec
// seccomp profile and returns it if so. A profile CRD is not one, but content
// which is neither is an error, publishing it would create an artifact no
// consumer understands.
func (a *Artifact) runtimeSpecSeccompProfile(
	content []byte,
) (*specs.LinuxSeccomp, bool, error) {
	_, profileErr := a.ReadProfile(content)
	if profileErr == nil {
		return nil, false, nil
	}

	runtimeSpec, err := decodeRuntimeSpecSeccompProfile(content)
	if err != nil {
		return nil, false, errors.Join(ErrDecodeYAML, profileErr, err)
	}

	return runtimeSpec, true, nil
}

// validateRuntimeSpec runs the validation container runtimes apply to a
// KEP-6061 artifact and fails on content they reject, unless skip is set, in
// which case the findings are only logged. The size limit is runtime
// configuration rather than part of the format and only warns.
func (a *Artifact) validateRuntimeSpec(
	runtimeSpec *specs.LinuxSeccomp, content []byte, path string, skip bool,
) error {
	if err := seccomp.ValidateArtifact(runtimeSpec); err != nil {
		if !skip {
			return fmt.Errorf(
				"profile %s: %w", path, errors.Join(ErrRuntimeRestrictions, err),
			)
		}

		a.logger.Info(
			"Profile contains content container runtimes reject, "+
				"pushing it anyway because artifact validation is disabled",
			"file", path,
			"error", err.Error(),
		)
	}

	if int64(len(content)) > MaxRuntimeProfileSize {
		a.logger.Info(
			"Profile is larger than container runtimes accept by default",
			"file", path,
			"size", len(content),
			"limit", MaxRuntimeProfileSize,
		)
	}

	return nil
}

// decodeRuntimeSpecSeccompProfile decodes the content of a KEP-6061 artifact,
// a raw OCI runtime-spec seccomp profile. The content has to decode strictly
// into the runtime-spec type, so unknown fields and trailing data are
// rejected and defaultAction is required.
func decodeRuntimeSpecSeccompProfile(content []byte) (*specs.LinuxSeccomp, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	runtimeSpec := &specs.LinuxSeccomp{}
	if err := decoder.Decode(runtimeSpec); err != nil {
		return nil, fmt.Errorf("decode runtime-spec seccomp profile: %w", err)
	}

	if decoder.More() {
		return nil, ErrTrailingData
	}

	if runtimeSpec.DefaultAction == "" {
		return nil, ErrNoDefaultAction
	}

	return runtimeSpec, nil
}

// runtimeSpecSeccompProfileSpec converts the content of a KEP-6061 artifact
// into a SeccompProfileSpec. Fields the CRD cannot express, such as
// defaultErrnoRet, are dropped in the conversion. Values which do not fit the
// CRD, for example syscall argument values beyond the signed 64 bit range,
// are an error. Detection on push does not use this conversion, so profiles
// the CRD cannot hold are still published in the right format.
func runtimeSpecSeccompProfileSpec(
	content []byte,
) (*seccompprofileapi.SeccompProfileSpec, error) {
	if _, err := decodeRuntimeSpecSeccompProfile(content); err != nil {
		return nil, err
	}

	spec := &seccompprofileapi.SeccompProfileSpec{}
	if err := json.Unmarshal(content, spec); err != nil {
		return nil, fmt.Errorf("convert runtime-spec seccomp profile: %w", err)
	}

	return spec, nil
}
