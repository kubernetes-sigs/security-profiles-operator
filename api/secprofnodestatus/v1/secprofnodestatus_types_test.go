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

func TestLowerOfTwoStates(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		currentLowest ProfileState
		candidate     ProfileState
		want          ProfileState
	}{
		"installed beats nothing": {
			currentLowest: ProfileStateInstalled,
			candidate:     ProfileStateInstalled,
			want:          ProfileStateInstalled,
		},
		"pending is lower than installed": {
			currentLowest: ProfileStateInstalled,
			candidate:     ProfileStatePending,
			want:          ProfileStatePending,
		},
		"pending is lower than installed, reversed": {
			currentLowest: ProfileStatePending,
			candidate:     ProfileStateInstalled,
			want:          ProfileStatePending,
		},
		"error is lower than pending": {
			currentLowest: ProfileStatePending,
			candidate:     ProfileStateError,
			want:          ProfileStateError,
		},
		"error is lower than terminating": {
			currentLowest: ProfileStateTerminating,
			candidate:     ProfileStateError,
			want:          ProfileStateError,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, LowerOfTwoStates(tc.currentLowest, tc.candidate))
		})
	}
}

// An unset state is not in stateOrder, so it used to rank 0 and tie with
// ProfileStateError. With a strict ">" comparison the winner then depended on
// which node status happened to be visited first, making the overall profile
// status flap between Error and "" for the same set of nodes.
func TestLowerOfTwoStatesUnsetIsOrderIndependent(t *testing.T) {
	t.Parallel()

	const unset ProfileState = ""

	t.Run("unset never wins over error", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, ProfileStateError, LowerOfTwoStates(unset, ProfileStateError))
		require.Equal(t, ProfileStateError, LowerOfTwoStates(ProfileStateError, unset))
	})

	t.Run("unset is treated as the documented default", func(t *testing.T) {
		t.Parallel()

		require.Equal(t, ProfileStatePending, LowerOfTwoStates(unset, ProfileStateInstalled))
		require.Equal(t, ProfileStatePending, LowerOfTwoStates(ProfileStateInstalled, unset))
	})

	t.Run("never returns the empty state", func(t *testing.T) {
		t.Parallel()

		for _, other := range []ProfileState{
			ProfileStateError,
			ProfileStateTerminating,
			ProfileStatePartial,
			ProfileStateDisabled,
			ProfileStatePending,
			ProfileStateInProgress,
			ProfileStateInstalled,
			unset,
		} {
			require.NotEqual(t, unset, LowerOfTwoStates(unset, other))
			require.NotEqual(t, unset, LowerOfTwoStates(other, unset))
		}
	})
}
