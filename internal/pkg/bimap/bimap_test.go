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

package bimap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/bimap"
)

func TestNew(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, string]()
	assert.NotNil(t, actual, "should create an empty map")
}

func TestNewFromMap(t *testing.T) {
	t.Parallel()

	input := map[string]string{"1": "a", "2": "b", "3": "c"}
	actual := bimap.NewFromMap(input)

	for k, v := range input {
		assert.True(t, actual.Exists(k), "should find map item in forward direction")
		assert.True(t, actual.ExistsBackwards(v), "should find map item in backward diretion")
	}
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

func TestSize(t *testing.T) {
	t.Parallel()

	actual := bimap.New[string, int]()
	actual.Insert("test1", 1)
	actual.Insert("test2", 2)
	actual.Insert("test3", 3)
	assert.Equal(t, 3, actual.Size(), "should retrieve the right size from the map")
}
