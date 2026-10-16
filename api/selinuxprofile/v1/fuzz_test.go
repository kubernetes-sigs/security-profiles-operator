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

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzValidatePolicy checks that the validation of raw policies, which runs
// on untrusted input in the admission webhook, does not panic, and that an
// accepted policy cannot escape the block it gets wrapped in.
func FuzzValidatePolicy(f *testing.F) {
	for _, seed := range []string{
		"(allow container_t shadow_t (file (read open)))",
		"(((( )))) () (())",
		"(blockinherit container)\n(allow process container_file_t (file (read)))",
		"(blockinherit container ; the template\n)",
		") (typepermissive spc_t) (block x",
		"; (\n) (typepermissive spc_t) (block x ; )",
		"; (\r) (block x",
		"; \"x\r(\" \"\n) (block x",
		`(typetransition process tmp_t file "(" tmp_t)) (allow spc_t self (file (read))) (block x`,
		"( ; comment\n blockinherit ; comment\n spc ; )\n)",
		`("typepermissive" spc_t)`,
		"(\vtypepermissive spc_t)",
		"(typetransition process tmp_t file \"name\n)",
		"(type my_container_t) (typealias my_alias_t (my_container_t))",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, policy string) {
		profile := &RawSelinuxProfile{Spec: RawSelinuxProfileSpec{Policy: policy}}
		if profile.ValidatePolicy() != nil {
			return
		}

		// The parentheses of an accepted policy are balanced the way the
		// CIL parser counts them, so it ends inside its block.
		depth := 0

		require.NoError(t, scanCIL(policy, func(kind cilTokenKind, _ string) error {
			switch kind {
			case cilOpen:
				depth++
			case cilClose:
				depth--
				require.GreaterOrEqual(t, depth, 0, "policy %q closes its block", policy)
			case cilSymbol, cilString:
			}

			return nil
		}))
		require.Zero(t, depth, "policy %q", policy)

		// No comment or string of an accepted policy is still open at its
		// end, so a parenthesis on a line after it counts.
		escape := &RawSelinuxProfile{Spec: RawSelinuxProfileSpec{Policy: policy + "\n) (block x"}}
		require.Error(t, escape.ValidatePolicy(), "policy %q hides a closing parenthesis", policy)
	})
}
