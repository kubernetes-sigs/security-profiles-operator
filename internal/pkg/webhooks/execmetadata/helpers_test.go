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
	"slices"
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

func TestSetExecRequestUID(t *testing.T) {
	t.Parallel()

	const (
		key  = config.ExecRequestUIDEnvKey
		repl = key + "=new"
		fake = key + "=fake"
	)

	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", want: []string{"env", repl}},
		{name: "no env", in: []string{"ls"}, want: []string{"env", repl, "ls"}},
		{
			name: "env without the variable",
			in:   []string{"env", "A=b", "ls"},
			want: []string{"env", "A=b", repl, "ls"},
		},
		{
			name: "env with the variable",
			in:   []string{"env", "A=b", fake, "ls"},
			want: []string{"env", "A=b", repl, "ls"},
		},
		{
			name: "env by path",
			in:   []string{"/usr/bin/env", fake, "ls"},
			want: []string{"/usr/bin/env", repl, "ls"},
		},
		{
			name: "env without a command",
			in:   []string{"env"},
			want: []string{"env", repl},
		},
		{
			name: "ignore environment",
			in:   []string{"env", "-i", fake, "sh"},
			want: []string{"env", "-i", repl, "sh"},
		},
		{
			name: "ignore environment without the variable",
			in:   []string{"env", "--ignore-environment", "sh"},
			want: []string{"env", "--ignore-environment", repl, "sh"},
		},
		{
			name: "lone dash",
			in:   []string{"env", "-", "sh"},
			want: []string{"env", "-", repl, "sh"},
		},
		{
			name: "unset",
			in: []string{
				"env", "-u", key, "-u" + key, "--unset=" + key, "--unset", key, "sh",
			},
			want: []string{
				"env", "-u", key, "-u" + key, "--unset=" + key, "--unset", key, repl, "sh",
			},
		},
		{
			name: "other options",
			in: []string{
				"env", "-0", "--null", "-v", "--debug", "-C", "/", "-C/", "--chdir=/",
				"--chdir", "/", "sh",
			},
			want: []string{
				"env", "-0", "--null", "-v", "--debug", "-C", "/", "-C/", "--chdir=/",
				"--chdir", "/", repl, "sh",
			},
		},
		{
			name: "end of options",
			in:   []string{"env", "--", fake, "-i"},
			want: []string{"env", "--", repl, "-i"},
		},
		{
			name: "nested env",
			in:   []string{"env", "A=1", "env", fake, "sh"},
			want: []string{"env", "A=1", "env", repl, "sh"},
		},
		{
			name: "nested env unsetting the variable",
			in:   []string{"env", fake, "env", "-u", key, "sh"},
			want: []string{"env", repl, "env", "-u", key, repl, "sh"},
		},
		{
			name: "all assignments",
			in:   []string{"env", key + "=a", key + "=", "ls"},
			want: []string{"env", repl, repl, "ls"},
		},
		{
			name: "value with a newline",
			in:   []string{"env", key + "=a\nb", "ls"},
			want: []string{"env", repl, "ls"},
		},
		{
			// Arguments of the command keep their value.
			name: "argument of the command",
			in:   []string{"sh", "-c", "echo", fake},
			want: []string{"env", repl, "sh", "-c", "echo", fake},
		},
		{
			name: "argument after the command of env",
			in:   []string{"env", "ls", fake},
			want: []string{"env", repl, "ls", fake},
		},
		{
			// Only whole assignments of the variable match.
			name: "prefix and suffix",
			in:   []string{"env", "X" + fake, key},
			want: []string{"env", "X" + fake, repl, key},
		},
		{
			name: "split string",
			in:   []string{"env", "-S", fake + " sh"},
			want: []string{"env", repl, "env", "-S", fake + " sh"},
		},
		{
			name: "combined options",
			in:   []string{"env", "-iu", key, "-vC/", "sh"},
			want: []string{"env", "-iu", key, "-vC/", repl, "sh"},
		},
		{
			name: "combined options with an unknown one",
			in:   []string{"env", "-iS", fake + " sh"},
			want: []string{"env", repl, "env", "-iS", fake + " sh"},
		},
		{
			name: "lone dash after end of options",
			in:   []string{"env", "--", "-", "sh"},
			want: []string{"env", "--", "-", repl, "sh"},
		},
		{
			name: "long option with a value it does not take",
			in:   []string{"env", "--null=x", "sh"},
			want: []string{"env", repl, "env", "--null=x", "sh"},
		},
		{
			name: "abbreviated long option",
			in:   []string{"env", "--ignore", "sh"},
			want: []string{"env", repl, "env", "--ignore", "sh"},
		},
		{
			// A command can only start with an assignment through env.
			name: "assignment as command",
			in:   []string{fake, "A=b", "sh"},
			want: []string{"env", repl, "A=b", "sh"},
		},
		{
			name: "assignment as command before env",
			in:   []string{"A=b", "env", "-u", key, "sh"},
			want: []string{"env", "A=b", "env", "-u", key, repl, "sh"},
		},
		{
			name: "option as command",
			in:   []string{"-i", "sh"},
			want: []string{"env", "--", repl, "-i", "sh"},
		},
		{
			name: "missing option argument",
			in:   []string{"env", "-u"},
			want: []string{"env", repl, "env", "-u"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, setExecRequestUID(slices.Clone(tc.in), "new"))
		})
	}
}
