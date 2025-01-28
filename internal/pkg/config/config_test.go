/*
Copyright 2021 The Kubernetes Authors.

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
	"testing"
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
