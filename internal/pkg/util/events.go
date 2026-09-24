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

package util

import (
	"fmt"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
)

// MaxEventNoteLength is the longest note the API server accepts for an
// events.k8s.io/v1 Event. Longer notes get the whole event rejected.
const MaxEventNoteLength = 1024

const truncatedSuffix = "..."

// EventRecorder records events.k8s.io/v1 events.
type EventRecorder = events.EventRecorder

// EventRecorderProvider is the part of a controller-runtime manager that
// hands out event recorders.
type EventRecorderProvider interface {
	GetEventRecorder(name string) recorder.EventRecorder
}

// NewEventRecorder returns the events.k8s.io/v1 recorder of the provider for
// the given reporting controller name. Its notes get truncated to
// MaxEventNoteLength, so that long error messages still produce an event.
func NewEventRecorder(provider EventRecorderProvider, name string) EventRecorder {
	return &truncatingRecorder{provider.GetEventRecorder(name)}
}

type truncatingRecorder struct {
	events.EventRecorder
}

func (t *truncatingRecorder) Eventf(
	regarding, related runtime.Object, eventtype, reason, action, note string, args ...any,
) {
	t.EventRecorder.Eventf(
		regarding,
		related,
		eventtype,
		reason,
		action,
		"%s",
		TruncateEventNote(fmt.Sprintf(note, args...)),
	)
}

// TruncateEventNote shortens a note to at most MaxEventNoteLength bytes
// without splitting a UTF-8 sequence.
func TruncateEventNote(note string) string {
	if len(note) <= MaxEventNoteLength {
		return note
	}

	cut := MaxEventNoteLength - len(truncatedSuffix)
	for cut > 0 && !utf8.RuneStart(note[cut]) {
		cut--
	}

	return note[:cut] + truncatedSuffix
}

// EventNode returns a node object to use as regarding object of an event
// about the node itself, like a missing kernel feature.
func EventNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}
