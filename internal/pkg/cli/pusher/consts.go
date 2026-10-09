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

package pusher

import (
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
)

// DefaultInputFile defines the default input location for the pusher.
var DefaultInputFile = cli.DefaultFile

const (
	// FlagDisableSigning is the flag for skipping the artifact signature.
	FlagDisableSigning string = "disable-signing"

	// FlagDisableArtifactValidation is the flag for pushing runtime-spec
	// profiles which container runtimes would reject.
	FlagDisableArtifactValidation string = "disable-artifact-validation"

	// FlagPlainHTTP is the flag for talking to the registry over HTTP.
	FlagPlainHTTP string = cli.FlagPlainHTTP

	// FlagProfiles is the flag for defining the input file locations.
	FlagProfiles string = "profiles"

	// FlagUsername is the flag for defining the username for registry
	// authentication.
	FlagUsername string = cli.FlagUsername

	// FlagPasswordStdin is the flag for reading the password for registry
	// authentication from stdin.
	FlagPasswordStdin string = cli.FlagPasswordStdin

	// FlagAnnotations is the flag for setting custom annotations to the pushed
	// artifact.
	FlagAnnotations string = "annotations"

	// FlagPlatforms is the flag for defining the platforms to push.
	FlagPlatforms string = "platforms"

	// FlagOIDCDeviceFlow is the flag for signing in with the device flow
	// without a terminal.
	FlagOIDCDeviceFlow string = cli.FlagOIDCDeviceFlow

	// flagPlatformAlias is the alias of FlagPlatforms, the flag name of pull.
	flagPlatformAlias string = "platform"

	// flagProfileAlias is the alias of FlagProfiles, the flag name of run.
	flagProfileAlias string = "profile"
)
