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

package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/bimap"
)

func TestNew(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, string]()
	assert.NotNil(t, actual, "should create an empty map")
}

func TestInsert(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	v, ok := actual.Get("test")
	assert.True(t, ok, "should find element in forward direction")
	assert.Equal(t, 1, v, "should get element in forward direction")

	k, ok := actual.GetBackwards(1)
	assert.True(t, ok, "should find element in backward direction")
	assert.Equal(t, "test", k, "should find element in backward direction")
}

func TestExists(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	assert.True(t, actual.Exists("test"), "element should exist")
}

func TestExistsBackwards(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	assert.True(t, actual.ExistsBackwards(1), "element should exist")
}

func TestGet(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	v, ok := actual.Get("test")
	assert.True(t, ok, "should get element from map")
	assert.Equal(t, 1, v, "should get element from map in forward direction")
}

func TestGetBackwards(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	v, ok := actual.GetBackwards(1)
	assert.True(t, ok, "should get element from map")
	assert.Equal(t, "test", v, "should get element from map in backward direction")
}

func TestDelete(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	actual.Delete("test")
	assert.False(t, actual.Exists("test"), "should remove the element in forward direction")
	assert.False(t, actual.ExistsBackwards(1), "should remove the element in backward direction")
}

func TestDeleteBackwards(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test", 1)
	actual.DeleteBackwards(1)
	assert.False(t, actual.Exists("test"), "should remove the element in forward direction")
	assert.False(t, actual.ExistsBackwards(1), "should remove the element in backward direction")
}

func TestClear(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test1", 1)
	actual.Insert("test2", 2)
	actual.Clear()
	assert.Equal(t, 0, actual.Size(), "should remove all elements")
	assert.False(t, actual.Exists("test1"), "should remove the element in forward direction")
	assert.False(t, actual.ExistsBackwards(1), "should remove the element in backward direction")

	// The map has to stay usable after being cleared.
	actual.Insert("test3", 3)
	assert.Equal(t, 1, actual.Size(), "should accept elements again")

	value, ok := actual.Get("test3")
	assert.True(t, ok)
	assert.Equal(t, 3, value)
}

func TestSize(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test1", 1)
	actual.Insert("test2", 2)
	actual.Insert("test3", 3)
	assert.Equal(t, 3, actual.Size(), "should retrieve the right size from the map")
}

// A BiMap is a bijection: reusing either side has to evict the mapping it
// replaces. Without that the two directions desync and a reverse lookup returns
// a key that no longer maps to the value.
func TestInsertKeepsBijection(t *testing.T) {
	t.Parallel()

	t.Run("reusing a value evicts the old key", func(t *testing.T) {
		t.Parallel()

		m := bimap.New[string, int]()
		m.Insert("first", 1)
		m.Insert("second", 1)

		_, ok := m.Get("first")
		require.False(t, ok, "the old key must be gone")

		value, ok := m.Get("second")
		require.True(t, ok)
		require.Equal(t, 1, value)

		key, ok := m.GetBackwards(1)
		require.True(t, ok)
		require.Equal(t, "second", key)
		require.Equal(t, 1, m.Size())
	})

	t.Run("reusing a key evicts the old value", func(t *testing.T) {
		t.Parallel()

		m := bimap.New[string, int]()
		m.Insert("key", 1)
		m.Insert("key", 2)

		_, ok := m.GetBackwards(1)
		require.False(t, ok, "the old value must be gone")

		key, ok := m.GetBackwards(2)
		require.True(t, ok)
		require.Equal(t, "key", key)
		require.Equal(t, 1, m.Size())
	})

	t.Run("reinserting the same pair is a no-op", func(t *testing.T) {
		t.Parallel()

		m := bimap.New[string, int]()
		m.Insert("key", 1)
		m.Insert("key", 1)

		value, ok := m.Get("key")
		require.True(t, ok)
		require.Equal(t, 1, value)
		require.Equal(t, 1, m.Size())
	})
}
