/*
Copyright 2020 The Kubernetes Authors.

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

package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionText(t *testing.T) {
	sut := Get()
	require.NotEmpty(t, sut.BuildDate)
	require.NotEmpty(t, sut.Compiler)
	require.NotEmpty(t, sut.GitCommit)
	require.NotEmpty(t, sut.GitTreeState)
	require.NotEmpty(t, sut.GitVersion)
	require.NotEmpty(t, sut.GoVersion)
	require.NotEmpty(t, sut.Platform)
	require.NotEmpty(t, sut.String())
}

func TestVersionJSON(t *testing.T) {
	sut, err := Get().JSONString()
	require.Nil(t, err)
	require.NotEmpty(t, sut)
}
