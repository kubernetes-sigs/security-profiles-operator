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

package enricher

import "testing"

func Test_extractSPORequestUID(t *testing.T) {
	t.Parallel()

	type args struct {
		input string
	}

	tests := []struct {
		name      string
		args      args
		want      string
		foundWant bool
	}{
		{
			name:      "Basic test with cmdline having SPO_EXEC_REQUEST_UID",
			args:      args{input: "env SPO_EXEC_REQUEST_UID=dbbf5fca-c955-4922-99d2-27a50212071c ls"},
			want:      "dbbf5fca-c955-4922-99d2-27a50212071c",
			foundWant: true,
		},
		{
			name:      "Test with no value",
			args:      args{input: "ls"},
			want:      "",
			foundWant: false,
		},
		{
			name:      "Test with other env values",
			args:      args{input: "env INVALID=dbbf5fca-c955-4922-99d2-27a50212071c ls"},
			want:      "",
			foundWant: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, got1 := extractSPORequestUID(tt.args.input)

			if got != tt.want {
				t.Errorf("extractSPORequestUID() got = %v, want %v", got, tt.want)
			}

			if got1 != tt.foundWant {
				t.Errorf("extractSPORequestUID() got1 = %v, want %v", got1, tt.foundWant)
			}
		})
	}
}
