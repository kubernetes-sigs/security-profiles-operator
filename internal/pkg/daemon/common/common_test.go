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

package common

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func Test_GetSPODNameNonDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "customSPODName")

	require.Equal(t, "customSPODName", GetSPODName())
}

func Test_GetSPODNameDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "")

	require.Equal(t, config.SPOdName, GetSPODName())
}

func Test_AuditTimeToIso(t *testing.T) {
	t.Parallel()

	isoTimestamp, err := AuditTimeToIso("1746611740.574:325")
	require.NoError(t, err)
	require.Equal(t, "2025-05-07T09:55:40.000Z", isoTimestamp)

	_, errInvalid1 := AuditTimeToIso("invalid")
	require.Error(t, errInvalid1)

	_, errInvalid2 := AuditTimeToIso("invalid.invalid")
	require.Error(t, errInvalid2)
}
