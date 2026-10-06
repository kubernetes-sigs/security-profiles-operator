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

package common

import (
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ResyncPredicate passes the periodic resyncs of the daemon cache, which carry
// an unchanged resource version. They reinstall a profile which got removed or
// changed on the host. Use it with builder.WithPredicates on the watch of the
// profile itself: WithEventFilter would also apply it to the other watches of
// the controller.
var ResyncPredicate = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		return e.ObjectOld != nil && e.ObjectNew != nil &&
			e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion()
	},
}
