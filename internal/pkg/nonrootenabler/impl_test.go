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

package nonrootenabler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultImplMounted(t *testing.T) {
	t.Parallel()

	sut := &defaultImpl{}

	mounted, err := sut.Mounted("/")
	require.NoError(t, err)
	require.True(t, mounted)

	// An existing directory is not enough, it has to be a mount point.
	dir := filepath.Join(t.TempDir(), "kubelet")
	require.NoError(t, os.Mkdir(dir, 0o700))

	mounted, err = sut.Mounted(dir)
	require.NoError(t, err)
	require.False(t, mounted)

	_, err = sut.Mounted(filepath.Join(dir, "missing"))
	require.Error(t, err)
}
