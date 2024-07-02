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

package artifact

import (
	"errors"
	"time"
)

const (
	// defaultProfileYAML is the default name for the OCI artifact profile.
	defaultProfileYAML = "profile.yaml"

	// defaultTimeout is the default timeout for push and pull operations.
	defaultTimeout = 5 * time.Minute
)

// ErrDecodeYAML is the error returned if no matching type could be decoded on
// artifact pull.
var ErrDecodeYAML = errors.New("unable to decode YAML into seccomp, selinux or apparmor profile")

// PullResultType are the different types returned for a PullResult.
type PullResultType string

const (
	// PullResultTypeSeccompProfile is referencing a seccomp profile.
	PullResultTypeSeccompProfile PullResultType = "SeccompProfile"

	// PullResultTypeSelinuxProfile is referencing a SELinux profile.
	PullResultTypeSelinuxProfile PullResultType = "SelinuxProfile"

	// PullResultTypeApparmorProfile is referencing a AppArmor profile.
	PullResultTypeApparmorProfile PullResultType = "ApparmorProfile"
)
