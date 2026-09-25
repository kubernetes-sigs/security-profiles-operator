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
type containerKeys struct {
	l           sync.RWMutex
	byKey       map[uint64]string
	byContainer map[string]map[uint64]struct{}
}

func newContainerKeys() *containerKeys {
	return &containerKeys{
		byKey:       map[uint64]string{},
		byContainer: map[string]map[uint64]struct{}{},
	}
}

// Insert records that key belongs to containerID.
func (c *containerKeys) Insert(key uint64, containerID string) {
	c.l.Lock()
	defer c.l.Unlock()

	if oldID, ok := c.byKey[key]; ok && oldID != containerID {
		c.removeKeyFrom(oldID, key)
	}

	c.byKey[key] = containerID

	keys, ok := c.byContainer[containerID]
	if !ok {
		keys = map[uint64]struct{}{}
		c.byContainer[containerID] = keys
	}

	keys[key] = struct{}{}
}

// removeKeyFrom drops key from a container's set. Callers hold the lock.
func (c *containerKeys) removeKeyFrom(containerID string, key uint64) {
	keys := c.byContainer[containerID]
	delete(keys, key)

	if len(keys) == 0 {
		delete(c.byContainer, containerID)
	}
}

// Keys returns the sorted keys of containerID.
func (c *containerKeys) Keys(containerID string) []uint64 {
	c.l.RLock()
	defer c.l.RUnlock()

	return slices.Sorted(maps.Keys(c.byContainer[containerID]))
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
	}

	delete(c.byContainer, containerID)
}

// Clear forgets everything.
func (c *containerKeys) Clear() {
	c.l.Lock()
	defer c.l.Unlock()

	clear(c.byKey)
	clear(c.byContainer)
}

// Size returns the number of known keys.
func (c *containerKeys) Size() int {
	c.l.RLock()
	defer c.l.RUnlock()

	return len(c.byKey)
}
