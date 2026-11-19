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

	sut := newContainerKeys(maxKeysPerContainer)

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

	sut := newContainerKeys(maxKeysPerContainer)

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

	sut := newContainerKeys(maxKeysPerContainer)

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

	sut := newContainerKeys(maxKeysPerContainer)

	sut.Insert(1, "a")
	sut.Insert(2, "a")
	sut.Insert(3, "b")
	sut.Insert(2, "c")

	require.Equal(t, []uint64{1, 3}, sut.KeysOf([]string{"a", "b"}))

	var got []uint64

	sut.WithKeysOf([]string{"a"}, func(keys []uint64) { got = keys })
	require.Equal(t, []uint64{1}, got)
}

// TestContainerKeysLimitsKeysPerContainer asserts that a container cannot grow
// the table without bounds, while its known keys and other containers are not
// affected by the limit.
func TestContainerKeysLimitsKeysPerContainer(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys(2)

	require.True(t, sut.Insert(1, "a"))
	require.True(t, sut.Insert(2, "a"))
	require.False(t, sut.Insert(3, "a"))
	require.True(t, sut.Insert(2, "a"), "a known key is still accepted")
	require.True(t, sut.Insert(3, "b"))

	_, ok := sut.Get(3)
	require.True(t, ok)
	require.Equal(t, []uint64{1, 2}, sut.Keys("a"))

	// A freed slot can be used again.
	sut.Delete(1)
	require.True(t, sut.Insert(4, "a"))
	require.Equal(t, []uint64{2, 4}, sut.Keys("a"))
}

// TestContainerKeysTakeUnreported asserts that the mount namespace of every
// key gets reported once, that a claimed key is left out, and that the state
// goes with the key.
func TestContainerKeysTakeUnreported(t *testing.T) {
	t.Parallel()

	sut := newContainerKeys(4)

	require.True(t, sut.InsertWithMntns(3, 30, "a"))
	require.True(t, sut.InsertWithMntns(1, 10, "a"))
	require.True(t, sut.InsertWithMntns(2, 10, "a"))
	require.True(t, sut.Insert(4, "a"))
	require.False(t, sut.InsertWithMntns(5, 50, "a"), "over the limit")

	// A key claimed by the process which reports it itself is left out.
	sut.SetReported(3, true)
	require.Equal(t, []uint32{10}, sut.TakeUnreported("a"))
	require.Empty(t, sut.TakeUnreported("a"), "reported once")

	// A claim given up by a failed lookup gets reported later.
	sut.SetReported(3, false)
	require.Equal(t, []uint32{30}, sut.TakeUnreported("a"))

	// A key reused by another container is unreported there.
	require.True(t, sut.InsertWithMntns(3, 31, "b"))
	require.Equal(t, []uint32{31}, sut.TakeUnreported("b"))

	sut.SetReported(42, true)
	require.NotContains(t, sut.reported, uint64(42), "unknown key")

	sut.Delete(1)
	require.NotContains(t, sut.reported, uint64(1))

	sut.DeleteContainer("a")
	require.NotContains(t, sut.reported, uint64(2))
	require.Empty(t, sut.TakeUnreported("a"))

	sut.Clear()
	require.Empty(t, sut.reported)
	require.Empty(t, sut.mntnsByKey)
}

// Size returns the number of known keys.
func (c *containerKeys) Size() int {
	c.l.RLock()
	defer c.l.RUnlock()

	return len(c.byKey)
}
