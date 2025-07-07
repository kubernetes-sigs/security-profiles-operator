/*
Copyright 2025 The Kubernetes Authors.

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

package common

type OrderedMap struct {
	keys   []string
	values map[string]any
}

func NewOrderedMap() *OrderedMap {
	return &OrderedMap{
		keys:   make([]string, 0),
		values: make(map[string]any),
	}
}

func (om *OrderedMap) Put(key string, value any) {
	if _, exists := om.values[key]; !exists {
		// Append if it's new.
		om.keys = append(om.keys, key)
	}

	om.values[key] = value
}

func (om *OrderedMap) Get(key string) any {
	return om.values[key]
}

func (om *OrderedMap) Keys() []string {
	keysCopy := make([]string, len(om.keys))

	copy(keysCopy, om.keys)

	return keysCopy
}

func (om *OrderedMap) ForEach(fn func(key string, value any)) {
	for _, key := range om.keys {
		value := om.values[key]
		fn(key, value)
	}
}

func (om *OrderedMap) Values() map[string]any {
	return om.values
}

func (om *OrderedMap) BulkSet(keysAndValues ...any) {
	if len(keysAndValues)%2 != 0 {
		// Assign a special value so that we don't panic.
		// Logic is similar to the logger.
		keysAndValues = append(keysAndValues, "<nil>")
	}

	for i := 0; i < len(keysAndValues); i += 2 {
		if strVal, ok := keysAndValues[i].(string); ok {
			om.Put(strVal, keysAndValues[i+1])
		}
	}
}

func (om *OrderedMap) BulkGet() []any {
	keysAndValues := make([]any, 0, len(om.keys)*2)

	om.ForEach(func(key string, value any) {
		keysAndValues = append(keysAndValues, key, value)
	})

	return keysAndValues
}
