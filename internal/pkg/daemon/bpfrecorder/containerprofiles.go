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
// recorder finds the mount namespace to collect a profile from; a bijection
// would evict the first profile when the second one is inserted and the first
// would silently never be collected.
//
// Profile names are unique, so the reverse direction stays a plain map.
type containerProfiles struct {
	l sync.RWMutex
	// byContainer keeps insertion order, so Get is stable.
	byContainer map[string][]string
	byProfile   map[string]string
}

func newContainerProfiles() *containerProfiles {
	return &containerProfiles{
		byContainer: map[string][]string{},
		byProfile:   map[string]string{},
	}
}

// Insert records that profile is being recorded for containerID.
func (c *containerProfiles) Insert(containerID, profile string) {
	c.l.Lock()
	defer c.l.Unlock()

	// A profile belongs to exactly one container, so re-pointing it has to
	// detach it from the one it was on.
	if oldID, ok := c.byProfile[profile]; ok && oldID != containerID {
		c.removeProfileFrom(oldID, profile)
	}

	if !slices.Contains(c.byContainer[containerID], profile) {
		c.byContainer[containerID] = append(c.byContainer[containerID], profile)
	}

	c.byProfile[profile] = containerID
}

// removeProfileFrom drops profile from a container's list. Callers hold the lock.
func (c *containerProfiles) removeProfileFrom(containerID, profile string) {
	profiles := slices.DeleteFunc(c.byContainer[containerID], func(p string) bool {
		return p == profile
	})
	if len(profiles) == 0 {
		delete(c.byContainer, containerID)

		return
	}

	c.byContainer[containerID] = profiles
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

// GetAll returns every profile recorded for containerID.
func (c *containerProfiles) GetAll(containerID string) []string {
	c.l.RLock()
	defer c.l.RUnlock()

	return slices.Clone(c.byContainer[containerID])
}

// GetBackwards returns the container ID a profile is recorded for.
func (c *containerProfiles) GetBackwards(profile string) (string, bool) {
	c.l.RLock()
	defer c.l.RUnlock()

	containerID, ok := c.byProfile[profile]

	return containerID, ok
}

// Delete forgets a container and every profile recorded for it.
func (c *containerProfiles) Delete(containerID string) {
	c.l.Lock()
	defer c.l.Unlock()

	for _, profile := range c.byContainer[containerID] {
		delete(c.byProfile, profile)
	}

	delete(c.byContainer, containerID)
}

// Clear forgets everything.
func (c *containerProfiles) Clear() {
	c.l.Lock()
	defer c.l.Unlock()

	clear(c.byContainer)
	clear(c.byProfile)
}

// Size returns the number of containers being recorded.
func (c *containerProfiles) Size() int {
	c.l.RLock()
	defer c.l.RUnlock()

	return len(c.byContainer)
}
