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

package utils

import (
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// SafeRecorder is an event recorder that tolerates a nil recorder.
type SafeRecorder struct {
	recorder util.EventRecorder
}

func NewSafeRecorder(recorder util.EventRecorder) *SafeRecorder {
	return &SafeRecorder{recorder: recorder}
}

// Eventf records an events.k8s.io/v1 event, see util.EventRecorder.
func (sr *SafeRecorder) Eventf(
	regarding, related runtime.Object,
	eventtype, reason, action, note string,
	args ...any,
) {
	if sr == nil || sr.recorder == nil {
		return
	}

	sr.recorder.Eventf(regarding, related, eventtype, reason, action, note, args...)
}
