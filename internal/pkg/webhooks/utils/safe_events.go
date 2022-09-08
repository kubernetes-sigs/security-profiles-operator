/*
Copyright 2022 The Kubernetes Authors.

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
	"k8s.io/client-go/tools/record"
)

type SafeRecorder struct {
	recorder record.EventRecorder
}

func NewSafeRecorder(recorder record.EventRecorder) *SafeRecorder {
	return &SafeRecorder{recorder: recorder}
}

func (sr *SafeRecorder) Event(object runtime.Object, eventtype, reason, message string) {
	if sr.recorder == nil {
		return
	}

	sr.recorder.Event(object, eventtype, reason, message)
}

// Eventf is just like Event, but with Sprintf for the message field.
func (sr *SafeRecorder) Eventf(object runtime.Object, eventtype, reason, messageFmt string, args ...interface{}) {
	if sr.recorder == nil {
		return
	}

	sr.recorder.Eventf(object, eventtype, reason, messageFmt, args...)
}

// AnnotatedEventf is just like eventf, but with annotations attached.
func (sr *SafeRecorder) AnnotatedEventf(
	object runtime.Object,
	annotations map[string]string,
	eventtype, reason, messageFmt string,
	args ...interface{},
) {
	if sr.recorder == nil {
		return
	}

	sr.recorder.AnnotatedEventf(object, annotations, eventtype, reason, messageFmt, args...)
}
