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

package selinuxprofile

import (
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

func TestRawSelinuxProfileHandler(t *testing.T) {
	t.Parallel()

	profile := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "raw"},
		Spec: selinuxprofileapi.RawSelinuxProfileSpec{
			Policy: "(allow process self (file (read)))\n(allow process self (dir (search)))\n",
		},
	}
	cli := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(profile).Build()

	oh, err := newRawSelinuxProfileHandler(t.Context(), cli, types.NamespacedName{Name: "raw"})
	require.NoError(t, err)
	require.Equal(t, "raw", oh.GetProfileObject().GetName())
	require.NoError(t, oh.Validate(t.Context()))

	cil, err := oh.GetCILPolicy()
	require.NoError(t, err)
	require.Equal(
		t,
		"(block raw_\n    (allow process self (file (read)))\n    (allow process self (dir (search)))\n)",
		cil,
	)

	_, err = newRawSelinuxProfileHandler(t.Context(), cli, types.NamespacedName{Name: "missing"})
	require.True(t, kerrors.IsNotFound(err))
}

func TestRawSelinuxProfileHandlerRejectsBlockEscape(t *testing.T) {
	t.Parallel()

	profile := &selinuxprofileapi.RawSelinuxProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "raw"},
		Spec: selinuxprofileapi.RawSelinuxProfileSpec{
			Policy: ")(allow process self (file (read)))",
		},
	}
	cli := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(profile).Build()

	oh, err := newRawSelinuxProfileHandler(t.Context(), cli, types.NamespacedName{Name: "raw"})
	require.NoError(t, err)
	require.Error(t, oh.Validate(t.Context()))
}

func TestControllerNames(t *testing.T) {
	t.Parallel()

	selinux, ok := NewController().(*ReconcileSelinux)
	require.True(t, ok)
	require.Equal(t, "selinuxprofile-spod", selinux.Name())
	require.NotNil(t, selinux.SchemeBuilder())

	raw, ok := NewRawController().(*ReconcileSelinux)
	require.True(t, ok)
	require.Equal(t, "rawselinuxprofile-spod", raw.Name())
}
