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

package apparmorprofile

import (
	"errors"

	profilebaseapi "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	// ErrProfileExists is returned for a profile whose name the host already
	// uses for a profile of its own.
	ErrProfileExists = errors.New("profile exists")
	// ErrRuntimeProfile is returned for a profile named after the default
	// profile of a container runtime.
	ErrRuntimeProfile = errors.New("profile name is reserved for a container runtime")
	// ErrOperatorProfile is returned for a profile named after one of the
	// profiles which the operator installs for its own containers.
	ErrOperatorProfile = errors.New("profile name is reserved for the operator")
	// ErrInvalidProfile is returned for a profile whose policy cannot be
	// generated, which only a change of the profile fixes.
	ErrInvalidProfile = errors.New("invalid profile")
	// ErrHostPolicyFile is returned for a profile whose policy file at the
	// managed location belongs to the host, which only the host can resolve.
	ErrHostPolicyFile = errors.New("policy file belongs to the host")
)

// operatorProfiles are the profiles which the non-root enabler installs for
// the containers of the daemon. The policy files of both carry the ownership
// marker, so the ownership checks of InstallProfile and RemoveProfile cannot
// protect them from an AppArmorProfile of the same name.
var operatorProfiles = map[string]struct{}{
	config.SpoApparmorProfileName:         {},
	config.BpfRecorderApparmorProfileName: {},
}

// isOperatorProfile reports whether name is one of the profiles of the
// operator itself.
func isOperatorProfile(name string) bool {
	_, ok := operatorProfiles[name]

	return ok
}

type ProfileManager interface {
	// Enabled checks whether the given profile technology is supported and
	// enabled by the underlying systems in the host.
	Enabled() bool

	// KnownUnsupported reports whether the host is known not to support the
	// profile technology. Enabled is false as well if the detection failed,
	// like when the daemon cannot enter the host mount namespace, which
	// tells nothing about the profiles installed on the host.
	KnownUnsupported() bool

	// InstallProfile ensure the profile is installed/copied/loaded into the host.
	// ownedByUs reports that the caller has independent evidence that this
	// operator installed the profile, which makes it ours even when its policy
	// file predates the ownership marker: this node's status already records it
	// as installed, or it is one of the operator's own bundled profiles.
	InstallProfile(p profilebaseapi.StatusBaseUser, ownedByUs bool) (bool, error)

	// RemoveProfile ensure the profile is uninstalled/deleted/unloaded from the host.
	// ownedByUs reports that the caller has independent evidence that this
	// operator installed the profile on this node. It is what allows unloading
	// a profile whose policy file is gone, because a container runtime loads its
	// default profile without any file to establish ownership from. It reports
	// whether it unloaded the profile or removed its policy file, which it
	// does not for a profile which is not ours or not on the host.
	RemoveProfile(p profilebaseapi.StatusBaseUser, ownedByUs bool) (bool, error)
	// ProfileInstalled reports whether this operator installed the profile:
	// it is loaded into the kernel from a policy file which carries the
	// ownership marker.
	ProfileInstalled(p profilebaseapi.StatusBaseUser) (bool, error)
}
