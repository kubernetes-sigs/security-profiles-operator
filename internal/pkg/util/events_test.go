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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/recorder"
)

type fakeProvider struct {
	name string
	rec  *events.FakeRecorder
}

func (f *fakeProvider) GetEventRecorder(name string) recorder.EventRecorder {
	f.name = name

	return f.rec
}

func TestTruncateEventNote(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		note string
		want string
	}{
		{"empty", "", ""},
		{"short", "short note", "short note"},
		{"at limit", strings.Repeat("a", MaxEventNoteLength), strings.Repeat("a", MaxEventNoteLength)},
		{
			"over limit",
			strings.Repeat("a", MaxEventNoteLength+1),
			strings.Repeat("a", MaxEventNoteLength-len(truncatedSuffix)) + truncatedSuffix,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, TruncateEventNote(tc.note))
		})
	}
}

func TestTruncateEventNoteKeepsUTF8Valid(t *testing.T) {
	t.Parallel()

	// A three byte rune straddles the cut, it must not be split.
	note := strings.Repeat("a", MaxEventNoteLength-len(truncatedSuffix)-1) + strings.Repeat("€", 10)
	got := TruncateEventNote(note)

	require.LessOrEqual(t, len(got), MaxEventNoteLength)
	require.True(t, utf8.ValidString(got))
	require.True(t, strings.HasSuffix(got, truncatedSuffix))
}

func TestNewEventRecorder(t *testing.T) {
	t.Parallel()

	provider := &fakeProvider{rec: events.NewFakeRecorder(2)}
	rec := NewEventRecorder(provider, "controller")

	require.Equal(t, "controller", provider.name)

	node := EventNode("node-1")
	require.Equal(t, "node-1", node.Name)

	rec.Eventf(node, nil, corev1.EventTypeWarning, "Reason", EventActionInstall, "value %d%%", 50)
	require.Equal(t, "Warning Reason value 50%", <-provider.rec.Events)

	rec.Eventf(
		node,
		nil,
		corev1.EventTypeNormal,
		"Long",
		EventActionInstall,
		"%s",
		strings.Repeat("x", 2*MaxEventNoteLength),
	)
	require.Len(t, strings.TrimPrefix(<-provider.rec.Events, "Normal Long "), MaxEventNoteLength)
}
