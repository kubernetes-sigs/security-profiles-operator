//go:build !apparmor
// +build !apparmor

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

import (
	"errors"

	"github.com/go-logr/logr"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
)

var errAppArmorNotSupported = errors.New("apparmor not enabled in this build")

func (a *aaProfileManager) Enabled() bool {
	return false
}

func (a *aaProfileManager) RemoveProfile(profilebasev1alpha1.StatusBaseUser) error {
	return errAppArmorNotSupported
}

func (a *aaProfileManager) InstallProfile(profilebasev1alpha1.StatusBaseUser) (bool, error) {
	return false, errAppArmorNotSupported
}

func loadProfile(logr.Logger, string, string) (bool, error) {
	return false, errAppArmorNotSupported
}

func removeProfile(logr.Logger, string) error {
	return errAppArmorNotSupported
}
