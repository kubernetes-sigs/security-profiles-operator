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
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func Test_getEffectiveSPOdJsonEnricher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		dt                  daemonTunables
		nsIsSet             bool
		jsonEnricherOptsSet bool
		wantErr             bool
	}{
		{
			name: "Should correctly set the image",
			dt: daemonTunables{
				selinuxdImage:    "foo:bar",
				logEnricherImage: "bar:baz",
			},
			nsIsSet:             false,
			jsonEnricherOptsSet: false,
			wantErr:             false,
		},
		{
			name: "Should correctly set the namespace",
			dt: daemonTunables{
				selinuxdImage:    "foo:bar",
				logEnricherImage: "bar:baz",
				watchNamespace:   "watch-ns",
			},
			nsIsSet:             true,
			jsonEnricherOptsSet: false,
			wantErr:             false,
		},
		{
			name: "Should correctly set the json Enricher volume correctly",
			dt: daemonTunables{
				selinuxdImage:                  "foo:bar",
				logEnricherImage:               "bar:baz",
				jsonEnricherImage:              "foo:bar",
				jsonEnricherLogVolumeMountPath: "/var/log",
				jsonEnricherLogVolumeSource: &corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/tmp/audit.log",
					},
				},
			},
			nsIsSet:             false,
			jsonEnricherOptsSet: true,
			wantErr:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			//nolint:usetesting // cannot use tenv after t.Parallel()
			os.Setenv("OPERATOR_NAMESPACE", "default")

			got := getEffectiveSPOd(&tt.dt)
			require.Equal(t, tt.dt.selinuxdImage, got.Spec.Template.Spec.Containers[1].Image)
			require.Equal(t, tt.dt.logEnricherImage, got.Spec.Template.Spec.Containers[2].Image)

			var found bool

			for _, env := range got.Spec.Template.Spec.Containers[0].Env {
				if env.Name == config.RestrictNamespaceEnvKey {
					require.Equal(t, tt.dt.watchNamespace, env.Value)

					found = true

					break
				}
			}

			if tt.nsIsSet && !found {
				t.Errorf("%s env variable wasn't set", config.RestrictNamespaceEnvKey)
			}

			if tt.jsonEnricherOptsSet {
				require.Equal(t, tt.dt.jsonEnricherImage, got.Spec.Template.Spec.Containers[4].Image)
				require.Equal(t, tt.dt.jsonEnricherLogVolumeMountPath,
					got.Spec.Template.Spec.Containers[4].VolumeMounts[4].MountPath)
			}
		})
	}
}
