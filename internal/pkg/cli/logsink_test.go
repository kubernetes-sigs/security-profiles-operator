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

package cli

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLogSinkFormat(t *testing.T) {
	t.Parallel()

	errTest := errors.New("broken")

	for _, tc := range []struct {
		name          string
		sink          func() *LogSink
		err           error
		keysAndValues []any
		want          string
	}{
		{
			name: "message only",
			sink: func() *LogSink { return &LogSink{} },
			want: "Pulling profile",
		},
		{
			name:          "key and value",
			sink:          func() *LogSink { return &LogSink{} },
			keysAndValues: []any{"image", "registry/base:v1", "count", 2},
			want:          "Pulling profile (image=registry/base:v1, count=2)",
		},
		{
			name:          "key without value",
			sink:          func() *LogSink { return &LogSink{} },
			keysAndValues: []any{"image", "registry/base:v1", "count"},
			want:          "Pulling profile (image=registry/base:v1, count=<no value>)",
		},
		{
			name:          "error",
			sink:          func() *LogSink { return &LogSink{} },
			err:           errTest,
			keysAndValues: []any{"image", "registry/base:v1"},
			want:          "Pulling profile, err: broken (image=registry/base:v1)",
		},
		{
			name: "values of the sink come first",
			sink: func() *LogSink {
				sink, ok := (&LogSink{}).WithValues("component", "puller").(*LogSink)
				require.True(t, ok)

				return sink
			},
			keysAndValues: []any{"image", "registry/base:v1"},
			want:          "Pulling profile (component=puller, image=registry/base:v1)",
		},
		{
			name: "values of the sink only",
			sink: func() *LogSink {
				sink, ok := (&LogSink{}).WithValues("component", "puller").(*LogSink)
				require.True(t, ok)

				return sink
			},
			want: "Pulling profile (component=puller)",
		},
		{
			name: "nested names",
			sink: func() *LogSink {
				named, ok := (&LogSink{}).WithName("artifact").(*LogSink)
				require.True(t, ok)

				sink, ok := named.WithName("pull").(*LogSink)
				require.True(t, ok)

				return sink
			},
			want: "artifact/pull: Pulling profile",
		},
		{
			name: "name keeps the values",
			sink: func() *LogSink {
				withValues, ok := (&LogSink{}).WithValues("component", "puller").(*LogSink)
				require.True(t, ok)

				sink, ok := withValues.WithName("artifact").(*LogSink)
				require.True(t, ok)

				return sink
			},
			want: "artifact: Pulling profile (component=puller)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(
				t,
				tc.want,
				tc.sink().format("Pulling profile", tc.err, tc.keysAndValues...),
			)
		})
	}
}

// TestLogSinkWithValuesDoesNotShareValues verifies that sinks derived from
// the same parent do not see each other's values.
func TestLogSinkWithValuesDoesNotShareValues(t *testing.T) {
	t.Parallel()

	parent, ok := (&LogSink{}).WithValues("a", 1).(*LogSink)
	require.True(t, ok)

	first, ok := parent.WithValues("b", 2).(*LogSink)
	require.True(t, ok)

	second, ok := parent.WithValues("c", 3).(*LogSink)
	require.True(t, ok)

	require.Equal(t, "msg (a=1)", parent.format("msg", nil))
	require.Equal(t, "msg (a=1, b=2)", first.format("msg", nil))
	require.Equal(t, "msg (a=1, c=3)", second.format("msg", nil))
}
