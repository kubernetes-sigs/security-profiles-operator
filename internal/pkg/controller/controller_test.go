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

package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxConcurrentReconciles(t *testing.T) {
	t.Parallel()

	require.Equal(t, DefaultMaxConcurrentReconciles, MaxConcurrentReconciles(t.Context()))
	require.Equal(t, 7, MaxConcurrentReconciles(WithMaxConcurrentReconciles(t.Context(), 7)))
	require.Equal(
		t,
		7,
		Options(WithMaxConcurrentReconciles(t.Context(), 7)).MaxConcurrentReconciles,
	)

	// Invalid values fall back to the default.
	for _, n := range []int{0, -1} {
		require.Equal(t, DefaultMaxConcurrentReconciles,
			MaxConcurrentReconciles(WithMaxConcurrentReconciles(t.Context(), n)))
	}

	require.Equal(t, DefaultMaxConcurrentReconciles, MaxConcurrentReconciles(
		context.WithValue(t.Context(), MaxConcurrentReconcilesKey, "7"),
	))
}
