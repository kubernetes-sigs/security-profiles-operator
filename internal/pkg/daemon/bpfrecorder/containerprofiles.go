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
	"slices"
	"sync"
)

// containerProfiles maps container IDs to the profiles being recorded for them,
// and back.
//
// This is deliberately not a bijection. A single container carries one
// recording annotation per profile kind, so a pod recorded for both seccomp and
// AppArmor produces two profiles for the same container ID. Every one of them
// has to resolve back to that container, because that reverse lookup is how the
// recorder finds the recorded data to collect a profile from.
//
// A profile can also belong to several containers: a restarted container gets
// a new ID but carries the same annotation, and the profile has to cover what
// every run of it did.
type containerProfiles struct {
	l sync.RWMutex
	// Both directions keep insertion order, so Get is stable.
	byContainer map[string][]string
	byProfile   map[string][]string
	// generations holds the latest recording generation which cached the
	// profiles of a container.
	generations map[string]uint64
}

func newContainerProfiles() *containerProfiles {
	return &containerProfiles{
		byContainer: map[string][]string{},
		byProfile:   map[string][]string{},
		generations: map[string]uint64{},
	}
}

// InsertAt records that profile is being recorded for containerID by the
// recording of the generation.
func (c *containerProfiles) InsertAt(containerID, profile string, generation uint64) {
	c.l.Lock()
	defer c.l.Unlock()

	c.generations[containerID] = max(c.generations[containerID], generation)

	if !slices.Contains(c.byContainer[containerID], profile) {
		c.byContainer[containerID] = append(c.byContainer[containerID], profile)
	}

	if !slices.Contains(c.byProfile[profile], containerID) {
		c.byProfile[profile] = append(c.byProfile[profile], containerID)
	}
}

// Get returns the first profile recorded for containerID.
func (c *containerProfiles) Get(containerID string) (string, bool) {
	c.l.RLock()
	defer c.l.RUnlock()

	profiles := c.byContainer[containerID]
	if len(profiles) == 0 {
		return "", false
	}

	return profiles[0], true
}

// Containers returns the containers a profile is recorded for.
func (c *containerProfiles) Containers(profile string) []string {
	c.l.RLock()
	defer c.l.RUnlock()

	return slices.Clone(c.byProfile[profile])
}

// DeleteAt forgets a container and drops it from every profile recorded for
// it, if the latest recording which cached the container is the one of the
// generation.
func (c *containerProfiles) DeleteAt(containerID string, generation uint64) {
	c.l.Lock()
	defer c.l.Unlock()

	if c.generations[containerID] != generation {
		return
	}

	c.delete(containerID)
}

// delete forgets a container and drops it from every profile recorded for
// it, for callers holding the lock.
func (c *containerProfiles) delete(containerID string) {
	for _, profile := range c.byContainer[containerID] {
		c.byProfile[profile] = without(c.byProfile[profile], containerID)
		if len(c.byProfile[profile]) == 0 {
			delete(c.byProfile, profile)
		}
	}

	delete(c.byContainer, containerID)
	delete(c.generations, containerID)
}

// DeleteProfile forgets a single profile. It returns the containers the
// profile was recorded for, and those of them which have no profile left to be
// recorded for.
func (c *containerProfiles) DeleteProfile(profile string) (containerIDs, unused []string) {
	c.l.Lock()
	defer c.l.Unlock()

	containerIDs = c.byProfile[profile]

	for _, containerID := range containerIDs {
		c.byContainer[containerID] = without(c.byContainer[containerID], profile)
		if len(c.byContainer[containerID]) == 0 {
			delete(c.byContainer, containerID)
			delete(c.generations, containerID)

			unused = append(unused, containerID)
		}
	}

	delete(c.byProfile, profile)

	return containerIDs, unused
}

// Clear forgets everything.
func (c *containerProfiles) Clear() {
	c.l.Lock()
	defer c.l.Unlock()

	clear(c.byContainer)
	clear(c.byProfile)
	clear(c.generations)
}

// Size returns the number of containers being recorded.
func (c *containerProfiles) Size() int {
	c.l.RLock()
	defer c.l.RUnlock()

	return len(c.byContainer)
}

func without(list []string, item string) []string {
	return slices.DeleteFunc(list, func(s string) bool { return s == item })
}
