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

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
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
			env:  []corev1.EnvVar{{Name: config.ExecRequestUIDEnvKey, Value: "x"}},
			want: []corev1.EnvVar{},
		},
		{
			name: "first of several",
			env:  []corev1.EnvVar{{Name: config.ExecRequestUIDEnvKey}, {Name: "A"}, {Name: "B"}},
			want: []corev1.EnvVar{{Name: "A"}, {Name: "B"}},
		},
		{
			// A duplicate must not survive to shadow the appended variable.
			name: "duplicates",
			env: []corev1.EnvVar{
				{Name: config.ExecRequestUIDEnvKey, Value: "a"},
				{Name: "A"},
				{Name: config.ExecRequestUIDEnvKey, Value: "b"},
				{Name: config.ExecRequestUIDEnvKey, Value: "c"},
			},
			want: []corev1.EnvVar{{Name: "A"}},
		},
		{
			name: "last of several",
			env:  []corev1.EnvVar{{Name: "A"}, {Name: config.ExecRequestUIDEnvKey}},
			want: []corev1.EnvVar{{Name: "A"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := removeExistingEnv(tc.env, config.ExecRequestUIDEnvKey)
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

	const repl = config.ExecRequestUIDEnvKey + "=new"

	for _, tc := range []struct {
		name     string
		in       []string
		want     []string
		replaced bool
		repl     string
	}{
		{name: "nil"},
		{name: "no match", in: []string{"env", "ls"}, want: []string{"env", "ls"}},
		{
			name:     "match",
			in:       []string{"env", config.ExecRequestUIDEnvKey + "=old", "ls"},
			want:     []string{"env", repl, "ls"},
			replaced: true,
		},
		{
			name:     "all matches",
			in:       []string{config.ExecRequestUIDEnvKey + "=a", config.ExecRequestUIDEnvKey + "="},
			want:     []string{repl, repl},
			replaced: true,
		},
		{
			// A "$" in the replacement is no group reference.
			name:     "dollar in replacement",
			in:       []string{config.ExecRequestUIDEnvKey + "=old"},
			want:     []string{config.ExecRequestUIDEnvKey + "=$1${0}$$"},
			replaced: true,
			repl:     config.ExecRequestUIDEnvKey + "=$1${0}$$",
		},
		{
			// Only whole arguments starting with the variable match.
			name: "prefix and suffix",
			in:   []string{"X" + config.ExecRequestUIDEnvKey + "=a", config.ExecRequestUIDEnvKey},
			want: []string{"X" + config.ExecRequestUIDEnvKey + "=a", config.ExecRequestUIDEnvKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			replacement := repl
			if tc.repl != "" {
				replacement = tc.repl
			}

			got, replaced := replaceRegexMatches(tc.in, execRequestUidRegex, replacement)
			require.Equal(t, tc.replaced, replaced)
			require.Equal(t, tc.want, got)
		})
	}
}
