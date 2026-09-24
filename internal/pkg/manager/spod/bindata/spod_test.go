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

package bindata

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func Test_CustomTemplatesVolume(t *testing.T) {
	t.Parallel()

	vol, mount := CustomTemplatesVolume("test-templates")

	require.Equal(t, SelinuxCustomTemplatesVolumeName, vol.Name)
	require.Equal(t, "test-templates", vol.ConfigMap.Name)
	require.Equal(t, SelinuxCustomTemplatesVolumeName, mount.Name)
	require.Equal(t, "/usr/share/selinuxd/templates", mount.MountPath)
	require.True(t, mount.ReadOnly)
}

func Test_CustomLogVolume(t *testing.T) {
	t.Parallel()

	volSource := &corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{
			Path: "/tmp/audit.log",
		},
	}

	_, volumeMount := CustomLogVolume("/tmp/log", volSource)
	require.Equal(t, "/tmp/log", volumeMount.MountPath)
}

func Test_KubeletDirVolume(t *testing.T) {
	t.Parallel()

	vol, mount := KubeletDirVolume("test-volume", "/mnt/resource/kubelet")

	require.Equal(t, "test-volume", vol.Name)
	require.NotNil(t, vol.HostPath)
	require.Equal(t, "/mnt/resource/kubelet", vol.HostPath.Path)
	require.Equal(t, corev1.HostPathDirectoryOrCreate, *vol.HostPath.Type)
	require.Equal(t, "test-volume", mount.Name)
	require.Equal(t, "/host/mnt/resource/kubelet", mount.MountPath)
	require.False(t, mount.ReadOnly)
}

// Test_ManifestDoesNotMountHostRoot asserts that the SPOd does not mount the
// host root filesystem or the whole of /var/lib, but only the kubelet and
// operator directories into the non-root enabler.
func Test_ManifestDoesNotMountHostRoot(t *testing.T) {
	t.Parallel()

	podSpec := Manifest.Spec.Template.Spec

	for i := range podSpec.Volumes {
		if hp := podSpec.Volumes[i].HostPath; hp != nil {
			require.NotContains(t, []string{"/", "/var", "/var/lib"}, hp.Path,
				"volume %s", podSpec.Volumes[i].Name)
		}
	}

	for _, containers := range [][]corev1.Container{podSpec.InitContainers, podSpec.Containers} {
		for i := range containers {
			for _, m := range containers[i].VolumeMounts {
				require.NotEqual(t, config.HostRoot, m.MountPath,
					"container %s mounts %s", containers[i].Name, m.Name)
			}
		}
	}

	nonRootEnabler := podSpec.InitContainers[InitContainerIDNonRootenabler]
	require.Contains(t, nonRootEnabler.VolumeMounts, corev1.VolumeMount{
		Name:      KubeletDirVolumeName,
		MountPath: path.Join(config.HostRoot, config.KubeletDir()),
	})
	require.Contains(t, nonRootEnabler.VolumeMounts, corev1.VolumeMount{
		Name:      "host-operator-volume",
		MountPath: config.OperatorRoot,
	})
}
