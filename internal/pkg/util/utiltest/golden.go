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
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// updateGolden rewrites the golden files with the current output instead of
// comparing against it: go test ./internal/... -update.
var updateGolden = flag.Bool(
	"update", false, "update the golden files instead of comparing against them",
)

// goldenDir is the directory of the golden files, relative to the package of
// the test, which is the working directory of a test binary.
const goldenDir = "testdata"

// Golden compares got with the content of testdata/<name>.golden in the
// package of the test. With the -update flag the file gets written instead, so
// that a reviewed change of the generated output is accepted by rerunning the
// test.
func Golden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join(goldenDir, name+".golden")

	if *updateGolden {
		require.NoError(t, os.MkdirAll(goldenDir, 0o750))
		require.NoError(t, os.WriteFile(path, got, 0o600))

		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // the golden file of the calling test
	require.NoError(
		t,
		err,
		"cannot read golden file %s, run the test with -update to create it",
		path,
	)
	require.Equal(t, string(want), string(got),
		"output differs from %s, run the test with -update to accept it", path)
}
