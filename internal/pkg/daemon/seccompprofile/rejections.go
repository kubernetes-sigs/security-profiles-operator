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

package seccompprofile

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// rejection identifies a rejected version of a profile. A rejection gets
// reported once, so that the resyncs of the daemon do not record an event and
// count an error for an unchanged profile every time.
type rejection struct {
	uid        types.UID
	generation int64
	reason     string
}

// newRejection returns the rejection of the current generation of obj for
// reason.
func newRejection(obj client.Object, reason string) rejection {
	return rejection{uid: obj.GetUID(), generation: obj.GetGeneration(), reason: reason}
}
