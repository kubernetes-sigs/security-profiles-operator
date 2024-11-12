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
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

func TestNameHashing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		prof      seccompprofile.SeccompProfile
		labelName string
	}{
		{
			name: "short name",
			prof: seccompprofile.SeccompProfile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SeccompProfile",
					APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "shortname-profile",
					Namespace: "security-profiles-operator",
				},
				Spec:   seccompprofile.SeccompProfileSpec{},
				Status: seccompprofile.SeccompProfileStatus{},
			},
			labelName: "SeccompProfile-shortname-profile",
		},
		{
			name: "long name",
			prof: seccompprofile.SeccompProfile{
				TypeMeta: metav1.TypeMeta{
					Kind:       "SeccompProfile",
					APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "this-is-a-very-long-name-surely-over-64-characters-omg-its-overflowing",
					Namespace: "security-profiles-operator",
				},
				Spec:   seccompprofile.SeccompProfileSpec{},
				Status: seccompprofile.SeccompProfileStatus{},
			},
			labelName: "SeccompProfile-9d42ecd8a72de861cc202ee69381e536088eec6dc43f8f8e",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			name := KindBasedDNSLengthName(&tc.prof)
			require.Equal(t, tc.labelName, name)
		})
	}
}
