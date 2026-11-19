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
	"maps"
	"slices"
	"sync"
)

// maxKeysPerContainer bounds the keys a single container can record under.
// Every nested cgroup or unshared mount namespace of a container gets its own
// key, and a workload creating them in a loop would fill the maps for every
// other recorded container.
const maxKeysPerContainer = 256

// containerKeys maps the recording keys reported by the BPF program to the
// containers they belong to, and back.
//
// A key is a cgroup ID or a mount namespace, see get_key in recorder.bpf.c.
// A container can own several keys: its processes may move to a nested cgroup,
// or unshare into a new mount namespace. A profile has to be built from all of
// them, otherwise it only covers whatever the most recent process did.
//
// A key belongs to one container only. Mount namespace inode numbers are
// reused once free, so a key reported by a new container is detached from the
// container it belonged to before.
//
// A container owns at most maxPerContainer keys, so that a workload creating
// nested cgroups or mount namespaces in a loop cannot grow the tables without
// bounds.
type containerKeys struct {
	l               sync.RWMutex
	byKey           map[uint64]string
	byContainer     map[string]map[uint64]struct{}
	maxPerContainer int

	// mntnsByKey is the mount namespace of the process which reported a key,
	// if known. A key equals its mount namespace only without unique keys,
	// see get_key in recorder.bpf.c.
	mntnsByKey map[uint64]uint32

	// reported holds the keys whose mount namespace got reported for the
	// profile of their container, see SetReported and TakeUnreported.
	reported map[uint64]struct{}
}

func newContainerKeys(maxPerContainer int) *containerKeys {
	return &containerKeys{
		byKey:           map[uint64]string{},
		byContainer:     map[string]map[uint64]struct{}{},
		maxPerContainer: maxPerContainer,
		mntnsByKey:      map[uint64]uint32{},
		reported:        map[uint64]struct{}{},
	}
}

// Insert records that key belongs to containerID. It reports false and records
// nothing if the container owns the maximum number of keys already.
func (c *containerKeys) Insert(key uint64, containerID string) bool {
	c.l.Lock()
	defer c.l.Unlock()

	return c.insert(key, containerID)
}

// InsertWithMntns is Insert, and also remembers the mount namespace of the
// process which reported the key, see MountNamespaces.
func (c *containerKeys) InsertWithMntns(key uint64, mntns uint32, containerID string) bool {
	c.l.Lock()
	defer c.l.Unlock()

	if !c.insert(key, containerID) {
		return false
	}

	c.mntnsByKey[key] = mntns

	return true
}

// insert is Insert for callers holding the lock.
func (c *containerKeys) insert(key uint64, containerID string) bool {
	keys, ok := c.byContainer[containerID]
	if _, owned := keys[key]; owned {
		return true
	}

	if len(keys) >= c.maxPerContainer {
		return false
	}

	if oldID, ok := c.byKey[key]; ok && oldID != containerID {
		c.removeKeyFrom(oldID, key)
	}

	c.byKey[key] = containerID

	if !ok {
		keys = map[uint64]struct{}{}
		c.byContainer[containerID] = keys
	}

	keys[key] = struct{}{}

	return true
}

// removeKeyFrom drops key from a container's set. Callers hold the lock.
func (c *containerKeys) removeKeyFrom(containerID string, key uint64) {
	keys := c.byContainer[containerID]
	delete(keys, key)
	delete(c.mntnsByKey, key)
	delete(c.reported, key)

	if len(keys) == 0 {
		delete(c.byContainer, containerID)
	}
}

// Get returns the container of key.
func (c *containerKeys) Get(key uint64) (string, bool) {
	c.l.RLock()
	defer c.l.RUnlock()

	containerID, ok := c.byKey[key]

	return containerID, ok
}

// Keys returns the sorted keys of containerID.
func (c *containerKeys) Keys(containerID string) []uint64 {
	c.l.RLock()
	defer c.l.RUnlock()

	return slices.Sorted(maps.Keys(c.byContainer[containerID]))
}

// SetReported marks whether the mount namespace of key got reported for the
// profile of its container. It does nothing for an unknown key.
func (c *containerKeys) SetReported(key uint64, reported bool) {
	c.l.Lock()
	defer c.l.Unlock()

	if _, ok := c.byKey[key]; !ok {
		return
	}

	if reported {
		c.reported[key] = struct{}{}
	} else {
		delete(c.reported, key)
	}
}

// TakeUnreported marks the keys of containerID with a known mount namespace
// as reported, and returns the sorted mount namespaces of the ones which were
// not reported before.
func (c *containerKeys) TakeUnreported(containerID string) []uint32 {
	c.l.Lock()
	defer c.l.Unlock()

	mntns := []uint32{}

	for key := range c.byContainer[containerID] {
		ns, ok := c.mntnsByKey[key]
		if !ok {
			continue
		}

		if _, reported := c.reported[key]; reported {
			continue
		}

		c.reported[key] = struct{}{}

		mntns = append(mntns, ns)
	}

	slices.Sort(mntns)

	return slices.Compact(mntns)
}

// KeysOf returns the sorted keys of all containerIDs.
func (c *containerKeys) KeysOf(containerIDs []string) []uint64 {
	c.l.RLock()
	defer c.l.RUnlock()

	return c.keysOf(containerIDs)
}

// keysOf is KeysOf for callers holding the lock.
func (c *containerKeys) keysOf(containerIDs []string) []uint64 {
	size := 0
	for _, containerID := range containerIDs {
		size += len(c.byContainer[containerID])
	}

	keys := make([]uint64, 0, size)

	for _, containerID := range containerIDs {
		keys = append(keys, slices.Collect(maps.Keys(c.byContainer[containerID]))...)
	}

	slices.Sort(keys)

	return slices.Compact(keys)
}

// WithKeysOf calls fn with the keys of containerIDs while holding the lock, so
// that a key which gets reused by another container in the meantime is not
// handed out.
func (c *containerKeys) WithKeysOf(containerIDs []string, fn func([]uint64)) {
	c.l.Lock()
	defer c.l.Unlock()

	fn(c.keysOf(containerIDs))
}

// Delete forgets key.
func (c *containerKeys) Delete(key uint64) {
	c.l.Lock()
	defer c.l.Unlock()

	if containerID, ok := c.byKey[key]; ok {
		c.removeKeyFrom(containerID, key)
		delete(c.byKey, key)
	}
}

// DeleteContainer forgets containerID and all of its keys.
func (c *containerKeys) DeleteContainer(containerID string) {
	c.l.Lock()
	defer c.l.Unlock()

	for key := range c.byContainer[containerID] {
		delete(c.byKey, key)
		delete(c.mntnsByKey, key)
		delete(c.reported, key)
	}

	delete(c.byContainer, containerID)
}

// Clear forgets everything.
func (c *containerKeys) Clear() {
	c.l.Lock()
	defer c.l.Unlock()

	clear(c.byKey)
	clear(c.byContainer)
	clear(c.mntnsByKey)
	clear(c.reported)
}

// Containers returns the containers which own a key.
func (c *containerKeys) Containers() []string {
	c.l.RLock()
	defer c.l.RUnlock()

	return slices.Collect(maps.Keys(c.byContainer))
}
