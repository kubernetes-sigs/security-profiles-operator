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

package spod

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_getEffectiveSPOd(t *testing.T) {
	tests := []struct {
		name    string
		dt      DaemonTunables
		nsIsSet bool
		wantErr bool
	}{
		{
			"Should correctly set the image",
			DaemonTunables{"foo:bar", "bar:baz", ""},
			false,
			false,
		},
		{
			"Should correctly set the namespace",
			DaemonTunables{"foo:bar", "bar:baz", "my-ns"},
			true,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getEffectiveSPOd(tt.dt)
			if (err != nil) != tt.wantErr {
				t.Errorf("getEffectiveSPOd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.dt.DaemonImage, got.Spec.Template.Spec.Containers[0].Image)
			require.Equal(t, tt.dt.NonRootEnablerImage, got.Spec.Template.Spec.InitContainers[0].Image)
			var found bool
			for _, env := range got.Spec.Template.Spec.Containers[0].Env {
				if env.Name == "RESTRICT_TO_NAMESPACE" {
					require.Equal(t, tt.dt.WatchNamespace, env.Value)
					found = true
					break
				}
			}
			if tt.nsIsSet && !found {
				t.Errorf("RESTRICT_TO_NAMESPACE env variable wasn't set")
			}
		})
	}
}
