/*
Copyright 2023 The Kubernetes Authors.

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

package cli

import (
	"runtime"
	"testing"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

func TestParsePlatform(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, input string
		assert      func(*v1.Platform, error)
	}{
		{
			name:  "success no input",
			input: "",
			assert: func(platform *v1.Platform, err error) {
				assert.NoError(t, err)
				assert.Equal(t, runtime.GOOS, platform.OS)
				assert.Equal(t, runtime.GOARCH, platform.Architecture)
				assert.Empty(t, platform.OSFeatures)
				assert.Empty(t, platform.OSVersion)
				assert.Empty(t, platform.Variant)
			},
		},
		{
			name:  "success only OS",
			input: "os",
			assert: func(platform *v1.Platform, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "os", platform.OS)
				assert.Equal(t, runtime.GOARCH, platform.Architecture)
				assert.Empty(t, platform.OSFeatures)
				assert.Empty(t, platform.OSVersion)
				assert.Empty(t, platform.Variant)
			},
		},
		{
			name:  "success OS and architecture",
			input: "os/arch",
			assert: func(platform *v1.Platform, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "os", platform.OS)
				assert.Equal(t, "arch", platform.Architecture)
				assert.Empty(t, platform.OSFeatures)
				assert.Empty(t, platform.OSVersion)
				assert.Empty(t, platform.Variant)
			},
		},
		{
			name:  "success OS, architecture and variant",
			input: "os/arch/var",
			assert: func(platform *v1.Platform, err error) {
				assert.NoError(t, err)
				assert.Equal(t, "os", platform.OS)
				assert.Equal(t, "arch", platform.Architecture)
				assert.Equal(t, "var", platform.Variant)
				assert.Empty(t, platform.OSFeatures)
				assert.Empty(t, platform.OSVersion)
			},
		},
		{
			name:  "failure too many parts",
			input: "os/arch/var/wrong",
			assert: func(platform *v1.Platform, err error) {
				assert.Error(t, err)
				assert.Nil(t, platform)
			},
		},
		{
			name:  "failure empty OS",
			input: "/arch/var",
			assert: func(platform *v1.Platform, err error) {
				assert.Error(t, err)
				assert.Nil(t, platform)
			},
		},
		{
			name:  "failure empty architecture",
			input: "os//var",
			assert: func(platform *v1.Platform, err error) {
				assert.Error(t, err)
				assert.Nil(t, platform)
			},
		},
	} {
		input := tc.input
		runAssert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runAssert(ParsePlatform(input))
		})
	}
}
