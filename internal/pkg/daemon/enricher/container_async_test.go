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

	"github.com/go-logr/logr"
	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/enricherfakes"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// TestRunDoesNotStallOnContainerLookup asserts that the lines of known
// containers are sent while another container is being looked up.
func TestRunDoesNotStallOnContainerLookup(t *testing.T) {
	t.Parallel()

	const unknownContainerID = "e1d4c1dbd3b5d9a4e9e2f6f5a1c8f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"

	lineChan := make(chan *types.AuditLine)
	release := make(chan struct{})

	mock := &enricherfakes.FakeImpl{}
	mock.StartTailReturns(lineChan, nil)
	mock.ContainerIDForPIDCalls(func(_ *ttlcache.Cache[string, string], pid int) (string, error) {
		if pid == 1 {
			return unknownContainerID, nil
		}

		return containerID, nil
	})
	mock.ListPodsCalls(func(context.Context, kubernetes.Interface, string) (*v1.PodList, error) {
		<-release

		return &v1.PodList{Items: []v1.Pod{{
			ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: namespace},
			Status: v1.PodStatus{
				ContainerStatuses: []v1.ContainerStatus{
					{ContainerID: crioPrefix + unknownContainerID},
				},
			},
		}}}, nil
	})

	sut, err := New(logr.Discard(), nil)
	require.NoError(t, err)

	sut.impl = mock
	sut.nodeName = node
	sut.metricsBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 5}
	sut.containerBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 1}
	sut.infoCache.Set(containerID, &types.ContainerInfo{
		PodName: pod, Namespace: namespace, ContainerID: containerID,
	}, ttlcache.DefaultTTL)

	//nolint:errcheck // Run only returns on shutdown.
	go func() { sut.Run() }()

	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 1}

	waitForCallCount(t, mock.ListPodsCallCount, 1)

	// The lookup hangs, the line of the known container is sent anyway.
	lineChan <- &types.AuditLine{AuditType: types.AuditTypeSeccomp, ProcessID: 2}

	waitForCallCount(t, mock.SendMetricCallCount, 1)
	require.Equal(t, 1, sut.auditLineCache.Len())

	// The finished lookup sends the backlog.
	close(release)

	waitForCallCount(t, mock.SendMetricCallCount, 2)
	waitForCallCount(t, sut.auditLineCache.Len, 0)
}

// TestAsyncContainerLookupDeduplicates asserts that a container is queued for
// a lookup only once.
func TestAsyncContainerLookupDeduplicates(t *testing.T) {
	t.Parallel()

	sut := newAsyncContainerLookup(&containerLookup{
		infoCache: ttlcache.New[string, *types.ContainerInfo](),
		missing:   newMissingContainerCache(),
		logger:    logr.Discard(),
	})

	for range 3 {
		_, err := sut.get(containerID)
		require.ErrorIs(t, err, errContainerLookupPending)
	}

	require.Len(t, sut.queue, 1)

	sut.lookup.missing.Set("missing", struct{}{}, ttlcache.DefaultTTL)

	_, err := sut.get("missing")
	require.ErrorIs(t, err, errContainerRecentlyMissing)
	require.Len(t, sut.queue, 1)
}
