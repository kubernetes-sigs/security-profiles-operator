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

import (
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/uuid"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func TestGetEnricherFilters(t *testing.T) {
	t.Parallel()

	type args struct {
		enricherFiltersJsonStr string
	}

	tests := []struct {
		name    string
		args    args
		want    []types.EnricherFilterOptions
		wantErr bool
	}{
		{
			name: "A best case with no filters",
			args: args{
				enricherFiltersJsonStr: "[]",
			},
			want:    make([]types.EnricherFilterOptions, 0),
			wantErr: false,
		},
		{
			name: "Bad Json",
			args: args{
				enricherFiltersJsonStr: "[",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "One filter",
			args: args{
				enricherFiltersJsonStr: "[{\"priority\":101, \"Level\":\"Metadata\"," +
					" \"matchKeys\":[\"namespace\"],\"matchValues\":[\"default\"]}]",
			},
			want: []types.EnricherFilterOptions{
				{Priority: 101, Level: "Metadata", MatchKeys: []string{"namespace"}, MatchValues: &[]string{"default"}},
			},
			wantErr: false,
		},
		{
			name: "One filter with int",
			args: args{
				enricherFiltersJsonStr: "[{\"priority\":101, \"Level\":\"Metadata\"," +
					" \"matchKeys\":[\"syscallID\"],\"matchValues\":[\"23\"]}]",
			},
			want: []types.EnricherFilterOptions{
				{Priority: 101, Level: "Metadata", MatchKeys: []string{"syscallID"}, MatchValues: &[]string{"23"}},
			},
			wantErr: false,
		},
		{
			name: "One filter without matchKeys",
			args: args{
				enricherFiltersJsonStr: "[{\"priority\":101, \"Level\":\"Metadata\"}]",
			},
			want: []types.EnricherFilterOptions{
				{Priority: 101, Level: "Metadata"},
			},
			wantErr: false,
		},
		{
			name: "Multiple filters",
			args: args{
				enricherFiltersJsonStr: "[{\"priority\":101, \"Level\":\"Metadata\"," +
					" \"matchKeys\":[\"namespace\"],\"matchValues\":[\"default\"]}," +
					"{\"priority\":999, \"Level\":\"None\"," +
					" \"matchKeys\":[\"msg\"],\"matchValues\":[\"audit\"]}]",
			},
			want: []types.EnricherFilterOptions{
				{Priority: 101, Level: "Metadata", MatchKeys: []string{"namespace"}, MatchValues: &[]string{"default"}},
				{Priority: 999, Level: "None", MatchKeys: []string{"msg"}, MatchValues: &[]string{"audit"}},
			},
			wantErr: false,
		},
		{
			name: "Multiple filters with JSON path and no value and sorting",
			args: args{
				enricherFiltersJsonStr: "[" +
					"{\"priority\":999, \"Level\":\"None\"," +
					" \"matchKeys\":[\"msg\"]}," +
					"{\"priority\":101, \"Level\":\"Metadata\"," +
					" \"matchKeys\":[\"resource/pod\"],\"matchValues\":[\"my-pod\"]}" +
					"]",
			},
			want: []types.EnricherFilterOptions{
				{Priority: 101, Level: "Metadata", MatchKeys: []string{"resource/pod"}, MatchValues: &[]string{"my-pod"}},
				{Priority: 999, Level: "None", MatchKeys: []string{"msg"}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetEnricherFilters(tt.args.enricherFiltersJsonStr, logr.Discard())
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEnricherFilters() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetEnricherFilters() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyEnricherFilters(t *testing.T) {
	t.Parallel()

	type args struct {
		logMap          map[string]any
		enricherFilters []types.EnricherFilterOptions
	}

	tests := []struct {
		name string
		args args
		want types.EnricherLogLevel
	}{
		{
			name: "Apply no filters",
			args: args{
				logMap:          map[string]any{},
				enricherFilters: make([]types.EnricherFilterOptions, 0),
			},
			want: types.EnricherLogLevelMetadata,
		},
		{
			name: "Apply no filters to a normal log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: make([]types.EnricherFilterOptions, 0),
			},
			want: types.EnricherLogLevelMetadata,
		},
		{
			name: "Apply basic filters to a normal log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 101, Level: "None", MatchKeys: []string{"version"}, MatchValues: &[]string{"spo/v1_alpha"}},
				},
			},
			want: types.EnricherLogLevelNone,
		},
		{
			name: "Apply basic filters to a normal log map and int",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"syscallID":  int32(50),
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 101, Level: "None", MatchKeys: []string{"syscallID"}, MatchValues: &[]string{"50"}},
				},
			},
			want: types.EnricherLogLevelNone,
		},
		{
			name: "Apply filters to a normal log map without match labels",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 101, Level: "None"},
				},
			},
			want: types.EnricherLogLevelMetadata,
		},
		{
			name: "Apply advanced path filters to a log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource": map[string]any{
						"pod": "my-pod",
					},
					"pid":       1234,
					"node":      nil,
					"syscalls":  "",
					"timestamp": "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 101, Level: "None", MatchKeys: []string{"resource/pod"}, MatchValues: &[]string{"my-pod"}},
				},
			},
			want: types.EnricherLogLevelNone,
		},
		{
			name: "Apply unmatched path filters to a log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 101, Level: "None", MatchKeys: []string{"hello"}},
				},
			},
			want: types.EnricherLogLevelMetadata,
		},
		{
			name: "Apply label only filters to a log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
					"requestUID": uuid.New().String(),
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 100, Level: "Metadata", MatchKeys: []string{"requestUID"}},
					{Priority: 999, Level: "None", MatchKeys: []string{"version"}, MatchValues: &[]string{"spo/v1_alpha"}},
				},
			},
			want: types.EnricherLogLevelMetadata,
		},
		{
			name: "Apply unmatched label only filters to a log map",
			args: args{
				logMap: map[string]any{
					"version":    "spo/v1_alpha",
					"auditID":    uuid.New().String(),
					"executable": "test",
					"cmdLine":    "test",
					"uid":        "test",
					"gid":        "test",
					"resource":   nil,
					"pid":        1234,
					"node":       nil,
					"syscalls":   "",
					"timestamp":  "test",
				},
				enricherFilters: []types.EnricherFilterOptions{
					{Priority: 100, Level: "Metadata", MatchKeys: []string{"requestUID"}},
					{Priority: 999, Level: "None", MatchKeys: []string{"version"}, MatchValues: &[]string{"spo/v1_alpha"}},
				},
			},
			want: types.EnricherLogLevelNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := ApplyEnricherFilters(tt.args.logMap, tt.args.enricherFilters); got != tt.want {
				t.Errorf("ApplyEnricherFilters() = %v, want %v", got, tt.want)
			}
		})
	}
}
