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
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// rejectionReports remembers the last reported rejection of each profile, so
// that the resyncs of the daemon do not record an event and count an error
// for an unchanged profile every time. The zero value is ready to use.
type rejectionReports struct {
	// reported holds the last reported rejection, keyed by the namespaced
	// name of the profile.
	reported sync.Map
}

// rejection identifies a rejected version of a profile.
type rejection struct {
	uid        types.UID
	generation int64
	reason     string
}

// shouldReport returns true if the rejection of obj for reason has to be
// reported, which is the case unless it got reported for the same generation
// of the profile already.
func (r *rejectionReports) shouldReport(obj client.Object, reason string) bool {
	current := rejection{uid: obj.GetUID(), generation: obj.GetGeneration(), reason: reason}
	previous, reported := r.reported.Swap(client.ObjectKeyFromObject(obj), current)

	return !reported || previous != current
}

// forget makes the next rejection of the profile of key get reported.
func (r *rejectionReports) forget(key types.NamespacedName) {
	r.reported.Delete(key)
}
