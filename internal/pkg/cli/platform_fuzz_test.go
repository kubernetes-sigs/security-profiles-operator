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

package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzParsePlatform verifies that a parsed platform always carries an OS and
// an architecture, and that formatting it as os/arch[/variant][:osversion]
// parses back to the same platform.
func FuzzParsePlatform(f *testing.F) {
	for _, seed := range []string{
		"",
		"linux",
		"linux/amd64",
		"linux/arm64/v8",
		"linux/arm/v7:1.2.3",
		"windows/amd64:10.0.17763.1234",
		"linux/amd64/",
		"/amd64",
		"linux/",
		"linux/amd64/v8/extra",
		":",
		"linux::",
		"/",
		"//",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		platform, err := ParsePlatform(input)
		if err != nil {
			require.Nil(t, platform)

			return
		}

		require.NotNil(t, platform)
		require.NotEmpty(t, platform.OS)
		require.NotEmpty(t, platform.Architecture)
		require.NotContains(t, platform.OS, "/")
		require.NotContains(t, platform.Architecture, "/")
		require.NotContains(t, platform.Variant, "/")

		formatted := platform.OS + "/" + platform.Architecture
		if platform.Variant != "" {
			formatted += "/" + platform.Variant
		}

		if platform.OSVersion != "" {
			formatted += ":" + platform.OSVersion
		}

		again, err := ParsePlatform(formatted)
		require.NoError(t, err)
		require.Equal(t, platform, again)
	})
}
