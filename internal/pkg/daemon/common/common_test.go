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

package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/utiltest"
)

func Test_GetSPODNameNonDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "customSPODName")

	require.Equal(t, "customSPODName", GetSPODName())
}

func Test_GetSPODNameDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "")

	require.Equal(t, config.SPOdName, GetSPODName())
}

// GetSPOD reads the SPOD from the namespace it is given, without looking at
// the environment for it.
func Test_GetSPOD(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "")
	t.Setenv(config.OperatorNamespaceEnvKey, "")

	cl := utiltest.NewFakeClient(t, &interceptor.Funcs{}, &spodapi.SecurityProfilesOperatorDaemon{
		ObjectMeta: metav1.ObjectMeta{Name: config.SPOdName, Namespace: "operator-ns"},
	})

	spod, err := GetSPOD(t.Context(), cl, "operator-ns")
	require.NoError(t, err)
	require.Equal(t, "operator-ns", spod.Namespace)

	_, err = GetSPOD(t.Context(), cl, "other-ns")
	require.True(t, kerrors.IsNotFound(err))
}

func Test_AuditTimeToIso(t *testing.T) {
	t.Parallel()

	isoTimestamp, err := AuditTimeToIso("1746611740.574:325")
	require.NoError(t, err)
	require.Equal(t, "2025-05-07T09:55:40.574Z", isoTimestamp)

	isoTimestamp, err = AuditTimeToIso("1746611740:325")
	require.NoError(t, err)
	require.Equal(t, "2025-05-07T09:55:40.000Z", isoTimestamp)

	_, errInvalid1 := AuditTimeToIso("invalid")
	require.Error(t, errInvalid1)

	_, errInvalid2 := AuditTimeToIso("invalid.invalid")
	require.Error(t, errInvalid2)
}

func TestAuditTime(t *testing.T) {
	t.Parallel()

	ts, err := AuditTime("1746611740.574:325")
	require.NoError(t, err)
	require.True(t, time.Unix(1746611740, 574*int64(time.Millisecond)).Equal(ts))

	_, err = AuditTime("invalid")
	require.Error(t, err)
}
