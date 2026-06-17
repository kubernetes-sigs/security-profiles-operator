/*
Copyright 2026 The Kubernetes Authors.

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

		// --- 4. False Positive Prevention ---
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
					require.Contains(t, err.Error(), tt.errContains, "Error message did not contain the expected substring")
				}
			} else {
				require.NoError(t, err, "ValidatePolicy() returned an unexpected error")
			}
		})
	}
}
