/*
Copyright 2021 The Kubernetes Authors.

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

import profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"

type ProfileManager interface {
	// Enabled checks whether the given profile technology is supported and
	// enabled by the underlying systems in the host.
	Enabled() bool

	// InstallProfile ensure the profile is installed/copied/loaded into the host.
	InstallProfile(p profilebasev1alpha1.StatusBaseUser) (bool, error)

	// RemoveProfile ensure the profile is uninstalled/deleted/unloaded from the host.
	RemoveProfile(p profilebasev1alpha1.StatusBaseUser) error
}
