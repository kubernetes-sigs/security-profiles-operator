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

package spod

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func Test_getEffectiveSPOdJsonEnricher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		dt                  daemonTunables
		nsIsSet             bool
		jsonEnricherOptsSet bool
	}{
		{
			name: "Should correctly set the image",
			dt:   daemonTunables{selinuxdImage: "foo:bar"},
		},
		{
			name: "Should correctly set the namespace",
			dt: daemonTunables{
				selinuxdImage:  "foo:bar",
				watchNamespace: "watch-ns",
			},
			nsIsSet: true,
		},
		{
			name: "Should correctly set the json Enricher volume correctly",
			dt: daemonTunables{
				selinuxdImage:                  "foo:bar",
				jsonEnricherLogVolumeMountPath: "/var/log",
				jsonEnricherLogVolumeSource: &corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/tmp/audit.log",
					},
				},
			},
			jsonEnricherOptsSet: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := getEffectiveSPOd(&tt.dt)
			podSpec := got.Spec.Template.Spec
			require.Equal(
				t,
				tt.dt.selinuxdImage,
				podSpec.Containers[bindata.ContainerIDSelinuxd].Image,
			)
			require.Equal(t, tt.dt.selinuxdImage,
				podSpec.InitContainers[bindata.InitContainerIDSelinuxSharedPoliciesCopier].Image)

			// The base SPOd must stay untouched.
			require.Equal(t, "quay.io/security-profiles-operator/selinuxd",
				bindata.Manifest.Spec.Template.Spec.Containers[bindata.ContainerIDSelinuxd].Image)

			env := podSpec.Containers[bindata.ContainerIDDaemon].Env
			idx := slices.IndexFunc(env, func(e corev1.EnvVar) bool {
				return e.Name == config.RestrictNamespaceEnvKey
			})

			if tt.nsIsSet {
				require.GreaterOrEqual(t, idx, 0)
				require.Equal(t, tt.dt.watchNamespace, env[idx].Value)
			} else {
				require.Equal(t, -1, idx)
			}

			jsonEnricher := podSpec.Containers[bindata.ContainerIDJsonEnricher]
			mountIdx := slices.IndexFunc(
				jsonEnricher.VolumeMounts,
				func(m corev1.VolumeMount) bool {
					return m.MountPath == tt.dt.jsonEnricherLogVolumeMountPath
				},
			)

			if tt.jsonEnricherOptsSet {
				require.GreaterOrEqual(t, mountIdx, 0)
			} else {
				require.Equal(t, -1, mountIdx)
			}
		})
	}
}

func Test_isStaticWebhook(t *testing.T) {
	t.Parallel()

	require.False(t, isStaticWebhook(t.Context()), "the webhook is managed per default")
	require.False(t, isStaticWebhook(context.WithValue(t.Context(), ManageWebhookKey, true)))
	require.True(t, isStaticWebhook(context.WithValue(t.Context(), ManageWebhookKey, false)))
	require.False(t, isStaticWebhook(context.WithValue(t.Context(), ManageWebhookKey, "false")),
		"a value of the wrong type is ignored")
}

func Test_isJsonEnricherVolumeNotConfigured(t *testing.T) {
	t.Parallel()

	require.True(t, isJsonEnricherVolumeNotConfigured(ErrJsonEnricherVolSourceNotFound))
	require.True(t, isJsonEnricherVolumeNotConfigured(ErrJsonEnricherVolMountPathNotFound))
	require.False(t, isJsonEnricherVolumeNotConfigured(errTest))
}

func operatorConfigMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: util.OperatorConfigMap, Namespace: testNamespace},
		Data:       data,
	}
}

func Test_getTunables(t *testing.T) {
	t.Setenv(config.RestrictNamespaceEnvKey, "watched")
	t.Setenv("RELATED_IMAGE_SELINUXD", "selinuxd:default")
	t.Setenv("RELATED_IMAGE_SELINUXD_EL9", "selinuxd:el9")
	t.Setenv(config.NodeNameEnvKey, "node")

	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node"},
		Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{
			OSImage:                 "Red Hat Enterprise Linux CoreOS 9",
			ContainerRuntimeVersion: "cri-o://1.30.0",
			KubeletVersion:          "v1.30.0",
		}},
	}

	logVolume, err := json.Marshal(&corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}})
	require.NoError(t, err)

	mapping := `[{"regex":"Red Hat Enterprise Linux CoreOS 9","imageFromVar":"RELATED_IMAGE_SELINUXD_EL9"}]`

	//nolint:paralleltest // the test sets the environment
	for name, tc := range map[string]struct {
		data       map[string]string
		getErr     error
		wantErr    bool
		wantVolume bool
	}{
		"without log volume": {data: map[string]string{util.SelinuxdImageMappingKey: mapping}},
		"with log volume": {
			data: map[string]string{
				util.SelinuxdImageMappingKey:         mapping,
				util.JsonEnricherLogVolumeSourceJson: string(logVolume),
				util.JsonEnricherLogVolumeMountPath:  "/logs",
			},
			wantVolume: true,
		},
		"invalid log volume": {
			data: map[string]string{
				util.SelinuxdImageMappingKey:         mapping,
				util.JsonEnricherLogVolumeSourceJson: "{",
			},
			wantErr: true,
		},
		"API error": {getErr: errTest, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := fake.NewClientBuilder().
				WithObjects(node, operatorConfigMap(tc.data)).
				WithInterceptorFuncs(interceptor.Funcs{
					Get: func(
						ctx context.Context, c client.WithWatch, key client.ObjectKey,
						obj client.Object, opts ...client.GetOption,
					) error {
						if tc.getErr != nil {
							return tc.getErr
						}

						return c.Get(ctx, key, obj, opts...)
					},
				}).
				Build()

			r := &ReconcileSPOd{clientReader: c, log: logf.Log, namespace: testNamespace}

			dt, err := r.getTunables(t.Context())
			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, "watched", dt.watchNamespace)
			require.Equal(t, "cri-o", dt.containerRuntime)
			require.Equal(t, "selinuxd:el9", dt.selinuxdImage)
			require.Equal(t, bindata.LocalSeccompProfilePath, dt.seccompLocalhostProfile)
			require.Equal(
				t,
				bindata.LocalSeccompBpfRecorderProfilePath,
				dt.bpfRecorderSeccompProfile,
			)

			if tc.wantVolume {
				require.NotNil(t, dt.jsonEnricherLogVolumeSource)
				require.Equal(t, "/logs", dt.jsonEnricherLogVolumeMountPath)
			} else {
				require.Nil(t, dt.jsonEnricherLogVolumeSource)
			}
		})
	}
}

func Test_defaultSPODCreator(t *testing.T) {
	t.Parallel()

	scheme := reconcileTestScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	creator := &defaultSPODCreator{client: c, namespace: testNamespace, staticWebhook: true}
	require.True(t, creator.NeedLeaderElection())
	require.NoError(t, creator.Start(t.Context()))

	created := &spodapi.SecurityProfilesOperatorDaemon{}
	key := client.ObjectKey{Name: config.SPOdName, Namespace: testNamespace}
	require.NoError(t, c.Get(t.Context(), key, created))
	require.True(t, *created.Spec.Webhook.StaticConfig)

	// An existing SPOD is kept as it is.
	created.Spec.Verbosity = 3
	require.NoError(t, c.Update(t.Context(), created))
	require.NoError(t, creator.Start(t.Context()))
	require.NoError(t, c.Get(t.Context(), key, created))
	require.Equal(t, int32(3), created.Spec.Verbosity)

	// Other errors are returned.
	failing := &defaultSPODCreator{
		client: fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return errTest
			},
		}).Build(),
		namespace: testNamespace,
	}
	require.ErrorIs(t, failing.Start(t.Context()), errTest)
}

func Test_isInNamespace(t *testing.T) {
	t.Parallel()

	require.False(t, isInNamespace(nil, testNamespace))
	require.True(t, isInNamespace(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace},
	}, testNamespace))
	require.False(t, isInNamespace(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other"},
	}, testNamespace))
}
