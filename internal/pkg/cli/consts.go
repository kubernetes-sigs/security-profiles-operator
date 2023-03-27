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

package cli

import (
	"os"
	"path/filepath"
)

const (
	// FlagProfile is the flag for defining the input file location.
	FlagProfile string = "profile"

	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = "output-file"

	// FlagUsername is the flag for defining the username for registry
	// authentication.
	FlagUsername string = "username"

	// EnvKeyPassword is the environment variable key for defining the password
	// for registry authentication.
	EnvKeyPassword string = "PASSWORD"
)

// DefaultFile defines the default input and output location for profiles.
var DefaultFile = filepath.Join(os.TempDir(), "profile.yaml")
