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

package bimap

import "sync"

// BiMap a bi-directional map which is safe to use concurrently.
type BiMap[K comparable, V comparable] struct {
	l        sync.RWMutex
	forward  map[K]V
	backward map[V]K
}

// New creates a new BiMap.
func New[K comparable, V comparable]() *BiMap[K, V] {
	return &BiMap[K, V]{
		forward:  map[K]V{},
		backward: map[V]K{},
	}
}

// NewFromMap creates a new BiMap from a normal map.
func NewFromMap[K comparable, V comparable](values map[K]V) *BiMap[K, V] {
	biMap := New[K, V]()
	for k, v := range values {
		biMap.Insert(k, v)
	}
	return biMap
}

// Insert inserts a new element in the BiMap.
func (m *BiMap[K, V]) Insert(k K, v V) {
	m.l.Lock()
	defer m.l.Unlock()

	m.forward[k] = v
	m.backward[v] = k
}

// Exists checks if an element exists in forward direction.
func (m *BiMap[K, V]) Exists(k K) bool {
	m.l.RLock()
	defer m.l.RUnlock()

	_, ok := m.forward[k]
	return ok
}

// ExistsBackwards checks if an element exists in backward direction.
func (m *BiMap[K, V]) ExistsBackwards(v V) bool {
	m.l.RLock()
	defer m.l.RUnlock()

	_, ok := m.backward[v]
	return ok
}

// Get returns an element from the map in forward direction if exists.
func (m *BiMap[K, V]) Get(k K) (V, bool) {
	m.l.RLock()
	defer m.l.RUnlock()
	v, ok := m.forward[k]
	return v, ok
}

// GetBackwards returns an element form the map in backward direction if exists.
func (m *BiMap[K, V]) GetBackwards(v V) (K, bool) {
	m.l.RLock()
	defer m.l.RUnlock()
	k, ok := m.backward[v]
	return k, ok
}

// Delete removes an element from the map by key in the forward direction.
func (m *BiMap[K, V]) Delete(k K) {
	v, ok := m.Get(k)
	if !ok {
		return
	}

	m.l.Lock()
	defer m.l.Unlock()
	delete(m.forward, k)
	delete(m.backward, v)
}

// DeleteBackwards deletes an element from the map by key in the backward direction.
func (m *BiMap[K, V]) DeleteBackwards(v V) {
	k, ok := m.GetBackwards(v)
	if !ok {
		return
	}

	m.l.Lock()
	defer m.l.Unlock()
	delete(m.forward, k)
	delete(m.backward, v)
}

// Size returns the size of the map.
func (m *BiMap[K, V]) Size() int {
	m.l.RLock()
	defer m.l.RUnlock()
	return len(m.forward)
}
