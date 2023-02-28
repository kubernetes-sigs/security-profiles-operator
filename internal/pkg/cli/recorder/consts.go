/*
Copyright 2023 The Kubernetes Authors.

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

package recorder

import (
	"os"
	"path/filepath"
)

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = "output-file"

	// FlagType is the flag for defining the recorder type.
	FlagType string = "type"
)

// Type is the enum for all available recorder types.
type Type string

const (
	// TypeSeccomp is the type indicating that we should record a seccomp CRD
	// profile.
	TypeSeccomp Type = "seccomp"

	// TypeRawSeccomp is the type indicating that we should record a raw
	// seccomp JSON profile.
	TypeRawSeccomp Type = "raw-seccomp"
)

// DefaultOutputFile defines the default output location for the recorder.
var DefaultOutputFile = filepath.Join(os.TempDir(), "profile.yaml")
