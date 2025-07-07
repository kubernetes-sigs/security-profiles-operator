/*
Copyright 2025 The Kubernetes Authors.

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

package common

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderedMap_Overall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		keyAndValues []any
		searchKey    string
		wantValue    any
		want         []any
	}{
		{
			name:         "Test with few key and values",
			keyAndValues: []any{"hello", "world"},
			searchKey:    "hello",
			wantValue:    "world",
			want:         []any{"hello", "world"},
		},
		{
			name:         "Test with odd key and values",
			keyAndValues: []any{"hello"},
			searchKey:    "hello",
			wantValue:    "<nil>",
			want:         []any{"hello", "<nil>"},
		},
		{
			name:         "Test with no values",
			keyAndValues: []any{},
			searchKey:    "",
			wantValue:    "",
			want:         []any{},
		},
		{
			name:         "Test with int values",
			keyAndValues: []any{"syscallid", 24},
			searchKey:    "syscallid",
			wantValue:    24,
			want:         []any{"syscallid", 24},
		},
		{
			name: "Test with map values",
			keyAndValues: []any{"resource", map[string]string{
				"pod": "mypod",
			}},
			searchKey: "resource",
			wantValue: map[string]string{
				"pod": "mypod",
			},
			want: []any{"resource", map[string]string{
				"pod": "mypod",
			}},
		},
		{
			name:         "Test ordering of keys",
			keyAndValues: []any{"zzz", 1, "aaa", 2, "nnnn", 3},
			searchKey:    "aaa",
			wantValue:    2,
			want:         []any{"zzz", 1, "aaa", 2, "nnnn", 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			om := NewOrderedMap()
			om.BulkSet(tt.keyAndValues...)

			if tt.searchKey != "" {
				require.Equal(t, tt.wantValue, om.Get(tt.searchKey))
				require.Equal(t, tt.wantValue, om.Values()[tt.searchKey])
			}

			if got := om.BulkGet(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BulkGet() = %v, want %v", got, tt.want)
			}
		})
	}
}
