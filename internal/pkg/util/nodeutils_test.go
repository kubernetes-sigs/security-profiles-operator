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

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
)

func nodeStatusList(nodeNames ...string) *secprofnodestatusapi.SecurityProfileNodeStatusList {
	list := &secprofnodestatusapi.SecurityProfileNodeStatusList{}
	for _, name := range nodeNames {
		list.Items = append(list.Items, secprofnodestatusapi.SecurityProfileNodeStatus{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: secprofnodestatusapi.SecurityProfileNodeStatusSpec{
				NodeName: name,
			},
		})
	}

	return list
}

// Node membership has to be an exact match. A substring match reports a removed
// node as still present whenever another node name contains it, which leaves
// the per-node finalizer in place and hangs the profile in Terminating.
func TestFinalizersMatchCurrentNodesExactMatch(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		currentNodes []string
		statusNodes  []string
		want         bool
	}{
		"all nodes present": {
			currentNodes: []string{"worker-1", "worker-2"},
			statusNodes:  []string{"worker-1", "worker-2"},
			want:         true,
		},
		"node removed": {
			currentNodes: []string{"worker-2"},
			statusNodes:  []string{"worker-1"},
			want:         false,
		},
		"removed node is a prefix of a remaining node": {
			// "worker-1" is gone but "worker-10" remains: a substring check
			// would wrongly report it as still present.
			currentNodes: []string{"worker-10"},
			statusNodes:  []string{"worker-1"},
			want:         false,
		},
		"removed node is a suffix of a remaining node": {
			currentNodes: []string{"eu-worker-1"},
			statusNodes:  []string{"worker-1"},
			want:         false,
		},
		"no statuses": {
			currentNodes: []string{"worker-1"},
			statusNodes:  nil,
			want:         true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := finalizersMatchNodeNames(tc.currentNodes, nodeStatusList(tc.statusNodes...))
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
