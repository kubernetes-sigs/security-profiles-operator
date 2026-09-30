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

package utiltest

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

// NewScheme returns a scheme with the Kubernetes built-in types, the
// OpenShift config API and all API groups of the operator, for fake clients
// in unit tests.
func NewScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()

	for _, addToScheme := range []func(*runtime.Scheme) error{
		clientgoscheme.AddToScheme,
		configv1.Install,
		apparmorprofileapi.AddToScheme,
		profilebindingapi.AddToScheme,
		profilerecordingapi.AddToScheme,
		seccompprofileapi.AddToScheme,
		secprofnodestatusapi.AddToScheme,
		selinuxprofileapi.AddToScheme,
		spodapi.AddToScheme,
	} {
		require.NoError(t, addToScheme(scheme))
	}

	return scheme
}
