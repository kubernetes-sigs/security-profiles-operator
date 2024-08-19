/*
Copyright 2025 The Kubernetes Authors.

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

package installer

import (
	"os"
	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/apparmorprofile"
)

type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	ReadFile(string) ([]byte, error)
	AppArmorEnabled(manager apparmorprofile.ProfileManager) bool
	AppArmorInstallProfile(manager apparmorprofile.ProfileManager, p profilebasev1alpha1.StatusBaseUser) (bool, error)
}

func (*defaultImpl) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (*defaultImpl) AppArmorEnabled(manager apparmorprofile.ProfileManager) bool {
	return manager.Enabled()
}

func (*defaultImpl) AppArmorInstallProfile(manager apparmorprofile.ProfileManager, p profilebasev1alpha1.StatusBaseUser) (bool, error) {
	return manager.InstallProfile(p)
}
