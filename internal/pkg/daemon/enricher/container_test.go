//go:build linux

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

package enricher

import (
	"context"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
)

// runningPod returns the pod of containerID once the kubelet reported the
// container.
func runningPod() *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
		Status: v1.PodStatus{
			ContainerStatuses: []v1.ContainerStatus{{
				Name:        "container",
				ContainerID: crioPrefix + containerID,
			}},
		},
	}
}

// creatingPod returns the pod of containerID while the container is created.
func creatingPod() *v1.Pod {
	creating := runningPod()
	creating.Status.ContainerStatuses[0].ContainerID = ""

	return creating
}

// watchPods has the container infos watch the pods of lw until the test ends,
// and waits for the initial list.
func watchPods(t *testing.T, containers *containerInfos, lw *podindextest.ListerWatcher) {
	t.Helper()

	mock := &enricherfakes.FakeImpl{}
	mock.PodListerWatcherReturns(lw)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	require.NoError(t, containers.watch(ctx, mock, node))
	require.Eventually(t, containers.pods.HasSynced, time.Minute, time.Millisecond)
}

func TestContainerInfoOf(t *testing.T) {
	t.Parallel()

	withAnnotations := func(annotations map[string]string) *v1.Pod {
		p := runningPod()
		p.Annotations = annotations
		p.Status.InitContainerStatuses = []v1.ContainerStatus{{
			Name: "init", ContainerID: "containerd://" + otherContainerID,
		}}

		return p
	}

	for name, tc := range map[string]struct {
		pod         *v1.Pod
		containerID string
		want        types.ContainerInfo
	}{
		"not recorded": {
			pod:         withAnnotations(nil),
			containerID: containerID,
			want: types.ContainerInfo{
				PodName: pod, Namespace: namespace, ContainerName: "container", ContainerID: containerID,
			},
		},
		"seccomp recording": {
			pod: withAnnotations(map[string]string{
				config.SeccompProfileRecordLogsAnnotationKey + "container": "seccomp-profile",
				config.SelinuxProfileRecordLogsAnnotationKey + "container": "selinux-profile",
			}),
			containerID: containerID,
			want: types.ContainerInfo{
				PodName: pod, Namespace: namespace, ContainerName: "container", ContainerID: containerID,
				RecordProfile: "seccomp-profile",
			},
		},
		"SELinux recording of an init container": {
			pod: withAnnotations(map[string]string{
				config.SeccompProfileRecordLogsAnnotationKey + "container": "seccomp-profile",
				config.SelinuxProfileRecordLogsAnnotationKey + "init":      "selinux-profile",
			}),
			containerID: otherContainerID,
			want: types.ContainerInfo{
				PodName: pod, Namespace: namespace, ContainerName: "init", ContainerID: otherContainerID,
				RecordProfile: "selinux-profile",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.want, *containerInfoOf(tc.pod, tc.containerID))
		})
	}
}

func TestContainerInfosGet(t *testing.T) {
	t.Parallel()

	t.Run("without pods", func(t *testing.T) {
		t.Parallel()

		sut := newContainerInfos()

		_, err := sut.get(containerID)
		require.ErrorIs(t, err, errNoContainerInfo)
		require.Nil(t, sut.changed())
	})

	t.Run("finds the containers the pods tell", func(t *testing.T) {
		t.Parallel()

		lw := podindextest.New(*creatingPod())
		sut := newContainerInfos()
		watchPods(t, sut, lw)

		_, err := sut.get(containerID)
		require.ErrorIs(t, err, errNoContainerInfo)

		changed := sut.changed()

		lw.Modify(runningPod())

		select {
		case <-changed:
		case <-time.After(time.Minute):
			require.Fail(t, "pod update not signalled")
		}

		info, err := sut.get(containerID)
		require.NoError(t, err)
		require.Equal(t, pod, info.PodName)
		require.Equal(t, "container", info.ContainerName)
	})

	t.Run("keeps the info of deleted pods", func(t *testing.T) {
		t.Parallel()

		lw := podindextest.New(*runningPod())
		sut := newContainerInfos()
		watchPods(t, sut, lw)

		_, err := sut.get(containerID)
		require.NoError(t, err)

		lw.Delete(runningPod())

		require.Eventually(t, func() bool {
			_, ok := sut.pods.Get(containerID)

			return !ok
		}, time.Minute, time.Millisecond)

		info, err := sut.get(containerID)
		require.NoError(t, err)
		require.Equal(t, pod, info.PodName)
	})

	t.Run("prefers the cache", func(t *testing.T) {
		t.Parallel()

		sut := newContainerInfos()
		sut.infoCache.Set(containerID, &types.ContainerInfo{PodName: "cached"}, ttlcache.DefaultTTL)

		info, err := sut.get(containerID)
		require.NoError(t, err)
		require.Equal(t, "cached", info.PodName)
	})
}
