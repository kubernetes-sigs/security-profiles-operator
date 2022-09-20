/*
Copyright 2020 The Kubernetes Authors.

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

package nodestatus

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// Expected shorten the node name if length exceed the limit.
//
//nolint:paralleltest
func TestShortenNodeName(t *testing.T) {
	cases := []struct {
		name              string
		nodeName          string
		wantFinalizerName string
	}{
		{
			name:              "NodeNameLongerThanLimit",
			nodeName:          "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename.internal",
			wantFinalizerName: "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename-deleted",
		},
		{
			name:              "NodeNameShorterThanLimit",
			nodeName:          "somenode-1234a.internal",
			wantFinalizerName: "somenode-1234a.internal-deleted",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.NodeNameEnvKey, tc.nodeName)
			sc, err := NewForProfile(nil, nil)
			require.NoError(t, err)

			require.Equal(t, tc.wantFinalizerName, sc.finalizerString)
		})
	}
}
