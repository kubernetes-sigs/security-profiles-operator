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

package bpfrecorder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainerKeysCollectsAllKeysOfAContainer(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys()

	// A process of the container unshared into a new mount namespace, or moved
	// to a nested cgroup: the profile has to cover both keys.
	sut.Insert(2, "a")
	sut.Insert(1, "a")
	sut.Insert(1, "a")

	require.Equal(t, []uint64{1, 2}, sut.Keys("a"))
	require.Equal(t, 2, sut.Size())
}

func TestContainerKeysReusedKeyMovesToNewContainer(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys()

	sut.Insert(1, "old")
	sut.Insert(2, "old")

	// The mount namespace inode number got reused by another container.
	sut.Insert(1, "new")

	require.Equal(t, []uint64{2}, sut.Keys("old"))
	require.Equal(t, []uint64{1}, sut.Keys("new"))

	sut.Insert(2, "new")
	require.Empty(t, sut.Keys("old"))
	require.Equal(t, []uint64{1, 2}, sut.Keys("new"))
}

func TestContainerKeysDelete(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys()

	sut.Insert(1, "a")
	sut.Insert(2, "a")
	sut.Insert(3, "b")

	sut.Delete(1)
	require.Equal(t, []uint64{2}, sut.Keys("a"))

	sut.DeleteContainer("a")
	require.Empty(t, sut.Keys("a"))
	require.Equal(t, 1, sut.Size())

	sut.Clear()
	require.Empty(t, sut.Keys("b"))
	require.Zero(t, sut.Size())
}

// TestContainerKeysWithKeysOf asserts that a key moved to another container is
// not handed out for the old one.
func TestContainerKeysWithKeysOf(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys()

	sut.Insert(1, "a")
	sut.Insert(2, "a")
	sut.Insert(3, "b")
	sut.Insert(2, "c")

	require.Equal(t, []uint64{1, 3}, sut.KeysOf([]string{"a", "b"}))

	var got []uint64

	sut.WithKeysOf([]string{"a"}, func(keys []uint64) { got = keys })
	require.Equal(t, []uint64{1}, got)
}
