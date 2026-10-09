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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetOperatorNamespace(t *testing.T) {
	// Note: this test cannot run in parallel because environment variables
	// are global resulting in random failures.
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{
			name:    "Valid one",
			want:    "default",
			wantErr: false,
		},
		{
			name:    "invalid one",
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OPERATOR_NAMESPACE", tt.want)

			got, err := TryToGetOperatorNamespace()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetOperatorNamespace() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if got != tt.want {
				t.Errorf("GetOperatorNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWatchNamespaces(t *testing.T) {
	// Note: this test cannot run in parallel because environment variables
	// are global.
	t.Setenv(RestrictNamespaceEnvKey, "")
	require.NoError(t, os.Unsetenv(RestrictNamespaceEnvKey))
	t.Setenv("WATCH_NAMESPACE", "watched")
	require.Equal(t, "watched", WatchNamespaces())

	t.Setenv(RestrictNamespaceEnvKey, "restricted")
	require.Equal(t, "restricted", WatchNamespaces())

	// An empty restriction is used as well.
	t.Setenv(RestrictNamespaceEnvKey, "")
	require.Empty(t, WatchNamespaces())
}
