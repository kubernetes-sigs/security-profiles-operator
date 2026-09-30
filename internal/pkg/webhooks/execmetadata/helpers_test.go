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

package execmetadata

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestRemoveExistingEnv(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		env  []corev1.EnvVar
		want []corev1.EnvVar
	}{
		{name: "nil"},
		{
			name: "missing",
			env:  []corev1.EnvVar{{Name: "A"}},
			want: []corev1.EnvVar{{Name: "A"}},
		},
		{
			name: "only",
			env:  []corev1.EnvVar{{Name: ExecRequestUid, Value: "x"}},
			want: []corev1.EnvVar{},
		},
		{
			// The order does not matter, the last element takes the place
			// of the removed one.
			name: "first of several",
			env:  []corev1.EnvVar{{Name: ExecRequestUid}, {Name: "A"}, {Name: "B"}},
			want: []corev1.EnvVar{{Name: "B"}, {Name: "A"}},
		},
		{
			name: "last of several",
			env:  []corev1.EnvVar{{Name: "A"}, {Name: ExecRequestUid}},
			want: []corev1.EnvVar{{Name: "A"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := removeExistingEnv(tc.env, ExecRequestUid)
			if tc.want == nil {
				require.Empty(t, got)

				return
			}

			require.Equal(t, tc.want, got)
		})
	}
}

func TestReplaceRegexMatches(t *testing.T) {
	t.Parallel()

	const repl = ExecRequestUid + "=new"

	for _, tc := range []struct {
		name     string
		in       []string
		want     []string
		replaced bool
	}{
		{name: "nil"},
		{name: "no match", in: []string{"env", "ls"}, want: []string{"env", "ls"}},
		{
			name:     "match",
			in:       []string{"env", ExecRequestUid + "=old", "ls"},
			want:     []string{"env", repl, "ls"},
			replaced: true,
		},
		{
			name:     "all matches",
			in:       []string{ExecRequestUid + "=a", ExecRequestUid + "="},
			want:     []string{repl, repl},
			replaced: true,
		},
		{
			// Only whole arguments starting with the variable match.
			name: "prefix and suffix",
			in:   []string{"X" + ExecRequestUid + "=a", ExecRequestUid},
			want: []string{"X" + ExecRequestUid + "=a", ExecRequestUid},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, replaced := replaceRegexMatches(tc.in, execRequestUidRegex, repl)
			require.Equal(t, tc.replaced, replaced)
			require.Equal(t, tc.want, got)
		})
	}
}
