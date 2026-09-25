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
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

func Test_populateCacheEntryForContainer(t *testing.T) {
	t.Parallel()

	falsely, truly := false, true

	type args struct {
		pod *v1.Pod
	}

	tests := []struct {
		name        string
		args        args
		want        int
		expectError bool
	}{
		{
			name:        "Empty containerID test",
			want:        1,
			expectError: true,
			args: args{
				pod: &v1.Pod{
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{
							{
								Name:         "no-container-id",
								Ready:        false,
								Image:        "nginx",
								ContainerID:  "",
								Started:      &falsely,
								RestartCount: 0,
								State: v1.ContainerState{
									Waiting: &v1.ContainerStateWaiting{
										Reason: "ContainerCreating",
									},
								},
							},
						},
						EphemeralContainerStatuses: []v1.ContainerStatus{
							{
								Name:         "debug-container",
								Ready:        true,
								Image:        "busybox",
								ContainerID:  "cri-o://4066a8e6f5e212076950d00c0cdeb9672e6b58c87bd31085720a8564e01ee021",
								Started:      &truly,
								RestartCount: 0,
								State: v1.ContainerState{
									Running: &v1.ContainerStateRunning{
										StartedAt: metav1.Time{
											Time: time.Now(),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "container which will not start does not hide the others",
			want:        1,
			expectError: false,
			args: args{
				pod: &v1.Pod{
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{
							{
								Name:        "no-image",
								ContainerID: "",
								State: v1.ContainerState{
									Waiting: &v1.ContainerStateWaiting{
										Reason: "ImagePullBackOff",
									},
								},
							},
							{
								Name:        "running",
								ContainerID: "cri-o://a7afc479dcef795780f76309b93f6087602f92e60cc352e01e89d596530d3bf3",
								State: v1.ContainerState{
									Running: &v1.ContainerStateRunning{},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "pod info fetch",
			want: 2,
			args: args{
				pod: &v1.Pod{
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{
							{
								Name:         "my-container",
								Ready:        true,
								Image:        "nginx",
								ContainerID:  "cri-o://a7afc479dcef795780f76309b93f6087602f92e60cc352e01e89d596530d3bf3",
								Started:      &truly,
								RestartCount: 0,
								State: v1.ContainerState{
									Running: &v1.ContainerStateRunning{
										StartedAt: metav1.Time{
											Time: time.Now(),
										},
									},
								},
							},
						},
						EphemeralContainerStatuses: []v1.ContainerStatus{
							{
								Name:         "debug-container",
								Ready:        true,
								Image:        "busybox",
								ContainerID:  "cri-o://4066a8e6f5e212076950d00c0cdeb9672e6b58c87bd31085720a8564e01ee021",
								Started:      &truly,
								RestartCount: 0,
								State: v1.ContainerState{
									Running: &v1.ContainerStateRunning{
										StartedAt: metav1.Time{
											Time: time.Now(),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "Without EphemeralContainerStatuses",
			want:        1,
			expectError: false,
			args: args{
				pod: &v1.Pod{
					Status: v1.PodStatus{
						ContainerStatuses: []v1.ContainerStatus{
							{
								Name:         "no-container-id",
								Ready:        false,
								Image:        "nginx",
								ContainerID:  "cri-o://4066a8e6f5e212076950d00c0cdeb9672e6b58c87bd31085720a8564e01ee021",
								Started:      &falsely,
								RestartCount: 0,
								State: v1.ContainerState{
									Waiting: &v1.ContainerStateWaiting{
										Reason: "ContainerCreating",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eg, _ := errgroup.WithContext(t.Context())

			infoCache := ttlcache.New(
				ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
				ttlcache.WithCapacity[string, *types.ContainerInfo](maxCacheItems),
			)

			populateCacheEntryForContainer(t.Context(), tt.args.pod, eg, infoCache, logr.Discard())

			err := eg.Wait()

			if !tt.expectError {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			if infoCache.Len() != tt.want {
				t.Errorf("populateCacheEntryForContainer() = %d, want %d", infoCache.Len(), tt.want)
			}
		})
	}
}

const (
	lookupTestPod         = "lookup-pod"
	lookupTestContainerID = "218ce99dd8b33f6f9b6565863d7cd47dc880963ddd2cd987bcb2d330c65144bf"
)

func newTestContainerLookup(mock *enricherfakes.FakeImpl) *containerLookup {
	return &containerLookup{
		nodeName: "lookup-node",
		impl:     mock,
		infoCache: ttlcache.New(
			ttlcache.WithTTL[string, *types.ContainerInfo](defaultCacheTimeout),
		),
		missing: newMissingContainerCache(),
		logger:  logr.Discard(),
		backoff: wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 3},
	}
}

func podList(statuses ...v1.ContainerStatus) *v1.PodList {
	return &v1.PodList{Items: []v1.Pod{{
		ObjectMeta: metav1.ObjectMeta{Name: lookupTestPod, Namespace: "lookup-namespace"},
		Status:     v1.PodStatus{ContainerStatuses: statuses},
	}}}
}

func TestGetContainerInfo(t *testing.T) {
	t.Parallel()

	creating := v1.ContainerStatus{
		Name: "creating",
		State: v1.ContainerState{
			Waiting: &v1.ContainerStateWaiting{Reason: "ContainerCreating"},
		},
	}
	running := v1.ContainerStatus{
		Name:        "running",
		ContainerID: "cri-o://" + lookupTestContainerID,
	}

	t.Run("stops retrying once the container is found", func(t *testing.T) {
		t.Parallel()

		mock := &enricherfakes.FakeImpl{}
		mock.ListPodsReturns(podList(creating, running), nil)

		sut := newTestContainerLookup(mock)

		info, err := sut.getContainerInfo(t.Context(), lookupTestContainerID)
		require.NoError(t, err)
		require.Equal(t, lookupTestPod, info.PodName)
		require.Equal(t, 1, mock.ListPodsCallCount())
	})

	t.Run("finds an init container listed while the others wait for it", func(t *testing.T) {
		t.Parallel()

		initializing := v1.ContainerStatus{
			Name: "main",
			State: v1.ContainerState{
				Waiting: &v1.ContainerStateWaiting{Reason: "PodInitializing"},
			},
		}
		initCreating := creating
		initCreating.Name = running.Name

		mock := &enricherfakes.FakeImpl{}
		mock.ListPodsReturnsOnCall(0, podList(initCreating, initializing), nil)
		mock.ListPodsReturns(podList(running, initializing), nil)

		sut := newTestContainerLookup(mock)

		info, err := sut.getContainerInfo(t.Context(), lookupTestContainerID)
		require.NoError(t, err)
		require.Equal(t, running.Name, info.ContainerName)
		require.Equal(t, 2, mock.ListPodsCallCount())
	})

	t.Run("remembers missing containers", func(t *testing.T) {
		t.Parallel()

		mock := &enricherfakes.FakeImpl{}
		mock.ListPodsReturns(podList(running), nil)

		sut := newTestContainerLookup(mock)

		_, err := sut.getContainerInfo(t.Context(), "unknown")
		require.ErrorIs(t, err, errNoContainerInfo)

		// Answered without listing all pods again.
		_, err = sut.getContainerInfo(t.Context(), "unknown")
		require.ErrorIs(t, err, errContainerRecentlyMissing)
		require.Equal(t, 1, mock.ListPodsCallCount())

		// Other containers are still looked up.
		_, err = sut.getContainerInfo(t.Context(), lookupTestContainerID)
		require.NoError(t, err)
	})

	t.Run("reports the retry error", func(t *testing.T) {
		t.Parallel()

		mock := &enricherfakes.FakeImpl{}
		mock.ListPodsReturns(podList(creating), nil)

		sut := newTestContainerLookup(mock)

		_, err := sut.getContainerInfo(t.Context(), lookupTestContainerID)
		require.ErrorIs(t, err, errContainerIDEmpty)
		require.Equal(t, 3, mock.ListPodsCallCount())
	})
}
