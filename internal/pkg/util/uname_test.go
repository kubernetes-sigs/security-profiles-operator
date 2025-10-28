//go:build linux

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

package util

import (
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/require"
)

func TestUname(t *testing.T) {
	t.Parallel()

	arch, version, err := Uname()
	require.NoError(t, err)
	require.True(t, version.GT(semver.Version{Major: 0, Minor: 0, Patch: 0}))
	require.NotEmpty(t, arch)
}

func TestNormalize(t *testing.T) {
	t.Parallel()

	require.Equal(t, "6.6.93", normalizeRelease("6.6.93"))
	require.Equal(t, "6.6.93", normalizeRelease("6.6.93+"))
	require.Equal(t, "6.6.93+extra", normalizeRelease("6.6.93+extra"))
}
