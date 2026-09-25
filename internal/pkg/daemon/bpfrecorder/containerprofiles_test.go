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
// reverse lookup fail for it, and the recorder resolves the data to collect
// from through exactly that lookup, so the profile would silently never be
// collected.
func TestContainerProfilesKeepsEveryProfileOfAContainer(t *testing.T) {
	t.Parallel()

	sut := newContainerProfiles()
	sut.Insert("container-1", "seccomp-profile")
	sut.Insert("container-1", "apparmor-profile")

	for _, profile := range []string{"seccomp-profile", "apparmor-profile"} {
		assert.Equal(t, []string{"container-1"}, sut.Containers(profile),
			"profile %s must resolve back to its container", profile)
	}

	assert.Equal(t, []string{"seccomp-profile", "apparmor-profile"}, sut.GetAll("container-1"))
	assert.Equal(t, 1, sut.Size(), "both profiles belong to one container")
}

// TestContainerProfilesKeepsRestartedContainers asserts that a restarted
// container, which gets a new ID but carries the same annotation, adds to the
// profile instead of replacing what the first run recorded.
func TestContainerProfilesKeepsRestartedContainers(t *testing.T) {
	t.Parallel()

	sut := newContainerProfiles()
	sut.Insert("first-run", "profile")
	sut.Insert("second-run", "profile")
	sut.Insert("second-run", "profile")

	assert.Equal(t, []string{"first-run", "second-run"}, sut.Containers("profile"))

	sut.Delete("first-run")
	assert.Equal(t, []string{"second-run"}, sut.Containers("profile"))
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

		assert.Empty(t, sut.Containers("nope"))
		assert.Empty(t, sut.GetAll("nope"))
	})

	t.Run("delete forgets the container and its profiles", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "seccomp")
		sut.Insert("container-1", "apparmor")
		sut.Insert("container-2", "other")

		sut.Delete("container-1")

		assert.Empty(t, sut.Containers("seccomp"))
		assert.Empty(t, sut.Containers("apparmor"))
		assert.Equal(t, []string{"container-2"}, sut.Containers("other"))
		assert.Equal(t, 1, sut.Size())
	})

	t.Run("clear forgets everything", func(t *testing.T) {
		t.Parallel()

		sut := newContainerProfiles()
		sut.Insert("container-1", "seccomp")
		sut.Insert("container-2", "apparmor")

		sut.Clear()

		assert.Equal(t, 0, sut.Size())
		assert.Empty(t, sut.Containers("seccomp"))
	})
}

func TestContainerProfilesDeleteProfile(t *testing.T) {
	t.Parallel()

	sut := newContainerProfiles()
	sut.Insert("container-1", "seccomp-profile")
	sut.Insert("container-1", "apparmor-profile")
	sut.Insert("container-2", "seccomp-profile")

	// Collecting one kind must leave the other one resolvable.
	assert.Equal(t, []string{"container-2"}, sut.DeleteProfile("seccomp-profile"))
	assert.Empty(t, sut.Containers("seccomp-profile"))
	assert.Equal(t, []string{"container-1"}, sut.Containers("apparmor-profile"))

	assert.Equal(t, []string{"container-1"}, sut.DeleteProfile("apparmor-profile"))
	assert.Zero(t, sut.Size())

	assert.Empty(t, sut.DeleteProfile("unknown"))
}
