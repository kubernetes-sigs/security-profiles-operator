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

package utils_test

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

func TestAppendIfNotExists(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		provided, expected []string
		item               string
	}{
		{
			provided: []string{},
			item:     "1",
			expected: []string{"1"},
		},
		{
			provided: []string{"1"},
			item:     "1",
			expected: []string{"1"},
		},
		{
			provided: []string{"2"},
			item:     "1",
			expected: []string{"2", "1"},
		},
	} {
		res := utils.AppendIfNotExists(tc.provided, tc.item)
		require.Equal(t, tc.expected, res)
	}
}

func TestRemoveIfExists(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		provided, expected []string
		item               string
	}{
		{
			provided: []string{},
			item:     "1",
			expected: []string{},
		},
		{
			provided: []string{"1"},
			item:     "1",
			expected: []string{},
		},
		{
			provided: []string{"2"},
			item:     "1",
			expected: []string{"2"},
		},
		{
			provided: []string{"1", "2", "3"},
			item:     "2",
			expected: []string{"1", "3"},
		},
	} {
		res := utils.RemoveIfExists(tc.provided, tc.item)
		require.Equal(t, tc.expected, res)
	}
}

func TestExists(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		provided []string
		item     string
		want     bool
	}{
		{
			provided: nil,
			item:     "",
			want:     false,
		},
		{
			provided: []string{},
			item:     "",
			want:     false,
		},
		{
			provided: []string{"a"},
			item:     "b",
			want:     false,
		},
		{
			provided: []string{"a", "b"},
			item:     "b",
			want:     true,
		},
	} {
		res := utils.Exists(tc.provided, tc.item)
		require.Equal(t, tc.want, res)
	}
}

type fakeClient struct {
	updateFails bool
}

func (f *fakeClient) Update(
	ctx context.Context,
	_ client.Object,
	_ ...client.UpdateOption,
) error {
	if f.updateFails {
		return errors.New("test")
	}
	return nil
}

func (*fakeClient) Patch(
	ctx context.Context,
	_ client.Object,
	_ client.Patch,
	_ ...client.PatchOption,
) error {
	return nil
}

func TestUpdateResource(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		client    *fakeClient
		shouldErr bool
	}{
		{ // success
			client: &fakeClient{},
		},
		{ // update fails
			client:    &fakeClient{updateFails: true},
			shouldErr: true,
		},
	} {
		err := utils.UpdateResource(
			context.Background(), logr.Discard(), tc.client, nil, "",
		)
		if tc.shouldErr {
			require.NotNil(t, err)
		} else {
			require.Nil(t, err)
		}
	}
}
