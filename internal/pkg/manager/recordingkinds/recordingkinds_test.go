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

package recordingkinds

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
)

// Every kind which a recording accepts has an entry, whose list holds objects
// of the kind.
func TestKinds(t *testing.T) {
	t.Parallel()

	for _, kind := range []profilerecordingapi.ProfileRecordingKind{
		profilerecordingapi.ProfileRecordingKindSeccompProfile,
		profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		profilerecordingapi.ProfileRecordingKindAppArmorProfile,
	} {
		k, ok := Of(kind)
		require.True(t, ok, kind)
		require.Equal(t, kind, k.Kind)

		list := k.NewList()
		require.NoError(t, meta.SetList(list, []runtime.Object{k.NewObject()}), kind)
		require.Equal(t, 1, meta.LenList(list))
	}

	_, ok := Of("unknown")
	require.False(t, ok)
}
