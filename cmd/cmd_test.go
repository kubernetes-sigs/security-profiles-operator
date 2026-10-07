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

package cmd

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The version is written to the writer of the app, which is stdout, so that
// it can be piped.
func TestVersionCommandWritesToAppWriter(t *testing.T) {
	t.Parallel()

	app, info := DefaultApp()

	var out bytes.Buffer

	app.Writer = &out

	require.NoError(t, app.Run([]string{"app", "version", "--json"}))

	got := map[string]any{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Equal(t, info.Version, got["version"])
}
