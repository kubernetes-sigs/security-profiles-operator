/*
Copyright 2021 The Kubernetes Authors.

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

package atomic

import "sync/atomic"

// Bool is an atomic boolean type.
type Bool int32

// Set can be used to set the atomic bool to a certain value.
func (b *Bool) Set(yes bool) {
	var value int32
	if yes {
		value = 1
	}

	atomic.StoreInt32((*int32)(b), value)
}

// Get can be used to retrieve the set value.
func (b *Bool) Get() bool {
	return atomic.LoadInt32((*int32)(b))&1 == 1
}
