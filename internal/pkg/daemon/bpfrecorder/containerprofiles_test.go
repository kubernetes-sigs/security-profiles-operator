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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContainerProfilesKeepsEveryProfileOfAContainer is the reason this is not a
// bijection. A pod selected by both a seccomp and an AppArmor ProfileRecording
// carries one annotation per kind, so findProfileForContainerID inserts twice
// under the same container ID. Evicting the first profile would make the
// reverse lookup fail for it, and the recorder resolves the mount namespace to
// collect from through exactly that lookup, so the profile would silently never
// be collected.
func TestContainerProfilesKeepsEveryProfileOfAContainer(t *testing.T) {
	t.Parallel()

	sut := newContainerProfiles()
	sut.Insert("container-1", "seccomp-profile")
	sut.Insert("container-1", "apparmor-profile")

	for _, profile := range []string{"seccomp-profile", "apparmor-profile"} {
		containerID, ok := sut.GetBackwards(profile)
		require.True(t, ok, "profile %s must resolve back to its container", profile)
		assert.Equal(t, "container-1", containerID)
	}

	assert.Equal(t, []string{"seccomp-profile", "apparmor-profile"}, sut.GetAll("container-1"))
	assert.Equal(t, 1, sut.Size(), "both profiles belong to one container")
}

func TestContainerProfiles(t *testing.T) {
	t.Parallel()

	t.Run("get returns the first profile", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "first")
		sut.Insert("container-1", "second")

		profile, ok := sut.Get("container-1")
		require.True(t, ok)
		assert.Equal(t, "first", profile)
	})

	t.Run("unknown lookups report missing", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()

		_, ok := sut.Get("nope")
		assert.False(t, ok)

		_, ok = sut.GetBackwards("nope")
		assert.False(t, ok)

		assert.Empty(t, sut.GetAll("nope"))
	})

	t.Run("inserting the same pair twice does not duplicate it", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "profile")
		sut.Insert("container-1", "profile")

		assert.Equal(t, []string{"profile"}, sut.GetAll("container-1"))
	})

	t.Run("a profile belongs to one container at a time", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "profile")
		sut.Insert("container-2", "profile")

		containerID, ok := sut.GetBackwards("profile")
		require.True(t, ok)
		assert.Equal(t, "container-2", containerID)

		// container-1 no longer holds it, and holds nothing else, so it is gone.
		assert.Empty(t, sut.GetAll("container-1"))
		assert.Equal(t, 1, sut.Size())
	})

	t.Run("delete forgets the container and all of its profiles", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "seccomp")
		sut.Insert("container-1", "apparmor")
		sut.Insert("container-2", "other")

		sut.Delete("container-1")

		_, ok := sut.GetBackwards("seccomp")
		assert.False(t, ok)
		_, ok = sut.GetBackwards("apparmor")
		assert.False(t, ok)

		containerID, ok := sut.GetBackwards("other")
		require.True(t, ok)
		assert.Equal(t, "container-2", containerID)
		assert.Equal(t, 1, sut.Size())
	})

	t.Run("clear forgets everything", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "seccomp")
		sut.Insert("container-2", "apparmor")

		sut.Clear()

		assert.Equal(t, 0, sut.Size())

		_, ok := sut.GetBackwards("seccomp")
		assert.False(t, ok)
	})
}
