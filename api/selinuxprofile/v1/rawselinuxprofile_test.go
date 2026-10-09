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

func TestValidatePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		policy      string
		wantErr     bool
		errContains string
	}{
		// --- 1. Basic String Validation ---
		{
			name:    "Valid basic policy",
			policy:  "(allow container_t shadow_t (file (read open)))",
			wantErr: false,
		},
		{
			name:        "Empty policy",
			policy:      "",
			wantErr:     true,
			errContains: "policy must not be empty",
		},
		{
			name:        "Whitespace only policy",
			policy:      "   \n\t  ",
			wantErr:     true,
			errContains: "policy must not be empty",
		},
		{
			name:        "Contains null byte",
			policy:      "(allow container_t \x00 shadow_t (file (read)))",
			wantErr:     true,
			errContains: "policy must not contain null bytes",
		},
		{
			name:        "Invalid UTF-8",
			policy:      string([]byte{0xff, 0xfe, 0xfd}),
			wantErr:     true,
			errContains: "policy must be valid UTF-8",
		},

		// --- 2. Parentheses Balancing (Block Escape Prevention) ---
		{
			name:        "Unmatched closing parenthesis (Block escape attack)",
			policy:      ") (typepermissive spc_t) (block x",
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},
		{
			name:        "Unbalanced open parenthesis",
			policy:      "(allow container_t (file (read)",
			wantErr:     true,
			errContains: "unbalanced parentheses",
		},
		{
			name:    "Deeply nested balanced parentheses",
			policy:  "(((( )))) () (())",
			wantErr: false,
		},

		// --- 3. Directive Restrictions (Global State Protection) ---
		{
			name: "Inherit a container template",
			policy: "(blockinherit container)\n" +
				"(allow process var_log_t (dir (open read)))\n( BLOCKINHERIT\tnet_container )",
			wantErr: false,
		},
		{
			name:        "Inherit another block",
			policy:      "(blockinherit permissive-profile_)",
			wantErr:     true,
			errContains: "must name a single template",
		},
		{
			name:        "Inherit a block which is not a container template",
			policy:      "(blockinherit spc)",
			wantErr:     true,
			errContains: "blockinherit of 'spc' is not allowed",
		},
		{
			name:        "Inherit a nested block",
			policy:      "(blockinherit container.process)",
			wantErr:     true,
			errContains: "must name a single template",
		},
		{
			name:        "Inherit more than one block at once",
			policy:      "(blockinherit container x)",
			wantErr:     true,
			errContains: "must name a single template",
		},
		{
			name:        "Restricted directive: typepermissive",
			policy:      "(typepermissive spc_t)",
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Restricted directive: classorder",
			policy:      "(classorder (file dir))",
			wantErr:     true,
			errContains: "restricted global directive 'classorder'",
		},
		{
			name:        "Restricted directive with irregular spacing/newlines",
			policy:      "( \t \n typepermissive spc_t)",
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Restricted directive with capitalization",
			policy:      "(TYPEPERMISSIVE spc_t)",
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Restricted directive embedded in larger policy",
			policy:      "(allow my_t my_test_t (file (read))) (mls (sensitivity s0))",
			wantErr:     true,
			errContains: "restricted global directive 'mls'",
		},
		{
			name: "Original CVE Attack Payload",
			policy: `(allow container_t self (capability (sys_admin))) ) 
			(typepermissive spc_t) (allow container_t shadow_t (file (read open))) (block x`,
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},

		// --- 4. Comments and Strings ---
		{
			name:        "Opening parenthesis in a comment",
			policy:      "; (\n) (typepermissive spc_t) (block x ; )",
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},
		{
			name:        "Comment ended by a carriage return",
			policy:      "; (\r) (block x",
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},
		{
			name:        "Carriage return in a string in a comment",
			policy:      "; \"x\r(\" \"\n) (block x",
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},
		{
			name:        "Opening parenthesis in a string",
			policy:      `(typetransition process tmp_t file "(" tmp_t)) (allow spc_t self (file (read))) (block x`,
			wantErr:     true,
			errContains: "unmatched closing parenthesis",
		},
		{
			name:        "Restricted directive after a comment",
			policy:      "( ; comment\n typepermissive spc_t)",
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Restricted directive as string",
			policy:      `("typepermissive" spc_t)`,
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Restricted directive next to a character CIL rejects",
			policy:      "(\vtypepermissive spc_t)",
			wantErr:     true,
			errContains: "restricted global directive 'typepermissive'",
		},
		{
			name:        "Blockinherit split by a comment",
			policy:      "( ; comment\n blockinherit ; comment\n spc ; )\n)",
			wantErr:     true,
			errContains: "blockinherit of 'spc' is not allowed",
		},
		{
			name:        "Inherit a string",
			policy:      `(blockinherit "container")`,
			wantErr:     true,
			errContains: "must name a single template",
		},
		{
			name:        "Unterminated string",
			policy:      "(typetransition process tmp_t file \"name\n)",
			wantErr:     true,
			errContains: "unterminated string",
		},
		{
			name: "Parentheses and directives in comments and strings",
			policy: "; (typepermissive spc_t) :)\n(blockinherit container) ; (block\n" +
				`(typetransition process tmp_t file "(block x" tmp_t)`,
			wantErr: false,
		},
		{
			name:    "Blockinherit with a trailing comment",
			policy:  "(blockinherit container ; the template\n)",
			wantErr: false,
		},

		// --- 5. False Positive Prevention ---
		{
			name:    "Restricted keyword used as an argument (Safe)",
			policy:  "(allow typepermissive file (read))",
			wantErr: false,
		},
		{
			name:    "Policy containing allowed directives similar to restricted ones",
			policy:  "(type my_container_t) (typealias my_alias_t (my_container_t))",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Mocking the RawSelinuxProfile struct
			sp := &RawSelinuxProfile{
				Spec: RawSelinuxProfileSpec{
					Policy: tt.policy,
				},
			}

			err := sp.ValidatePolicy()

			if tt.wantErr {
				require.Error(t, err, "ValidatePolicy() should have returned an error")

				if tt.errContains != "" {
					require.Contains(
						t,
						err.Error(),
						tt.errContains,
						"Error message did not contain the expected substring",
					)
				}
			} else {
				require.NoError(t, err, "ValidatePolicy() returned an unexpected error")
			}
		})
	}
}
