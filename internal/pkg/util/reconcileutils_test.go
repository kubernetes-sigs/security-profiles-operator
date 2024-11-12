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

package util

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestIgnoreNotFound(t *testing.T) {
	t.Parallel()

	profileName := "cool-profile"
	errOops := errors.New("oops")

	cases := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "IsErrorNotFound",
			err:  kerrors.NewNotFound(schema.GroupResource{}, profileName),
			want: nil,
		},
		{
			name: "OtherError",
			err:  errOops,
			want: errOops,
		},
		{
			name: "NilError",
			err:  nil,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := IgnoreNotFound(tc.err)
			require.Equal(t, tc.want, got)
		})
	}
}
