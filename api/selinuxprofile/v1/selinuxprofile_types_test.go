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

func TestSortLabelKeys(t *testing.T) {
	t.Parallel()

	requireSortedKeys(t, SortLabelKeys, nil, nil)
	requireSortedKeys(t, SortLabelKeys, Allow{}, nil)
	requireSortedKeys(t, SortLabelKeys, Allow{"var_log_t": {}}, []LabelKey{"var_log_t"})
	requireSortedKeys(t, SortLabelKeys,
		Allow{
			"var_log_t":     {},
			"http_port_t":   {},
			AllowSelf:       {},
			"proc_t":        {},
			"other.process": {},
			"Var_log_t":     {},
			"var-log_t":     {},
			"var.log_t":     {},
		},
		// The keys are compared byte wise, which the CIL output depends on.
		[]LabelKey{
			AllowSelf, "Var_log_t", "http_port_t", "other.process", "proc_t",
			"var-log_t", "var.log_t", "var_log_t",
		},
	)
}

func TestSortObjectClassKeys(t *testing.T) {
	t.Parallel()

	requireSortedKeys(t, SortObjectClassKeys, nil, nil)
	requireSortedKeys(t, SortObjectClassKeys, ObjectClassPermissions{}, nil)
	requireSortedKeys(t, SortObjectClassKeys,
		ObjectClassPermissions{"file": {"read"}}, []ObjectClassKey{"file"},
	)
	requireSortedKeys(t, SortObjectClassKeys,
		ObjectClassPermissions{
			"tcp_socket": {"name_bind"},
			"dir":        {"search"},
			"sock_file":  {"write"},
			"file":       {"read"},
			"filesystem": {"associate"},
		},
		[]ObjectClassKey{"dir", "file", "filesystem", "sock_file", "tcp_socket"},
	)
}

// requireSortedKeys requires sortKeys to return the keys of the map in the
// wanted order, or no keys if want is empty.
func requireSortedKeys[M ~map[K]V, K ~string, V any](
	t *testing.T, sortKeys func(M) []K, m M, want []K,
) {
	t.Helper()

	got := sortKeys(m)
	if len(want) == 0 {
		require.Empty(t, got)

		return
	}

	require.Equal(t, want, got)
}
