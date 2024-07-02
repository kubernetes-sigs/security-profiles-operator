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

package pusher

import (
	"runtime"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

var (
	// DefaultInputFile defines the default input location for the pusher.
	DefaultInputFile = cli.DefaultFile

	// DefaultPlatform defines the default platform for the current system.
	DefaultPlatform = &v1.Platform{
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
)

const (
	// FlagProfiles is the flag for defining the input file locations.
	FlagProfiles string = "profiles"

	// FlagUsername is the flag for defining the username for registry
	// authentication.
	FlagUsername string = cli.FlagUsername

	// FlagAnnotations is the flag for setting custom annotations to the pushed
	// artifact.
	FlagAnnotations string = "annotations"

	// FlagPlatforms is the flag for defining the platforms to push.
	FlagPlatforms string = "platforms"
)
