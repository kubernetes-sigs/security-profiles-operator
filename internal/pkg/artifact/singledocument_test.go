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

package artifact

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckSingleDocument(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		content       string
		wantErr       bool
		wantDecodeErr bool
	}{
		"single document":               {content: "kind: SeccompProfile\n"},
		"leading separator":             {content: "---\nkind: SeccompProfile\n"},
		"trailing empty document":       {content: "kind: SeccompProfile\n---\n# comment\n"},
		"json":                          {content: `{"defaultAction":"SCMP_ACT_ERRNO"}`},
		"empty":                         {},
		"two documents":                 {content: "kind: AppArmorProfile\n---\nkind: SeccompProfile\n", wantErr: true},
		"leading separator then two":    {content: "---\nkind: A\n---\nkind: B\n", wantErr: true},
		"content on the separator line": {content: "--- {apiVersion: v1, kind: SeccompProfile}\n"},
		"null document":                 {content: "kind: SeccompProfile\n--- null\n---\n~\n"},
		"invalid YAML":                  {content: "kind: [\n", wantDecodeErr: true},
		"two flow documents": {
			content: "--- {kind: A}\n--- {kind: B}\n", wantErr: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := CheckSingleDocument([]byte(tc.content))
			if tc.wantDecodeErr {
				require.ErrorIs(t, err, ErrDecodeYAML)

				return
			}

			if tc.wantErr {
				require.ErrorIs(t, err, ErrMultipleDocuments)

				return
			}

			require.NoError(t, err)
		})
	}
}
