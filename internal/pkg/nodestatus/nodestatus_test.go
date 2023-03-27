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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// Expected shorten the node name if length exceed the limit.
//
//nolint:paralleltest // cannot set environment variables in parallel tests
func TestShortenNodeName(t *testing.T) {
	cases := []struct {
		name              string
		nodeName          string
		wantFinalizerName string
		profileBase       profilebase.SecurityProfileBase
	}{
		{
			name:              "NodeNameLongerThanLimit",
			nodeName:          "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename.internal",
			wantFinalizerName: "somenode-1234a-hhbhz-worker-c-xswffw.c.testlongnodename-deleted",
			profileBase:       regularSeccompProfile(),
		},
		{
			name:              "NodeNameShorterThanLimit",
			nodeName:          "somenode-1234a.internal",
			wantFinalizerName: "somenode-1234a.internal-deleted",
			profileBase:       regularSeccompProfile(),
		},
		{
			name:              "PartialProfile",
			nodeName:          "somenode-1234a.internal",
			wantFinalizerName: partialProfileFinalizer,
			profileBase:       partialSeccompProfile(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(config.NodeNameEnvKey, tc.nodeName)
			sc, err := NewForProfile(tc.profileBase, nil)
			require.NoError(t, err)

			require.Equal(t, tc.wantFinalizerName, sc.finalizerString)
		})
	}
}

func regularSeccompProfile() *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
	}
}

func partialSeccompProfile() *seccompprofile.SeccompProfile {
	return &seccompprofile.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
			Labels: map[string]string{
				profilebase.ProfilePartialLabel: "true",
			},
		},
	}
}
