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

package podindex_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
)

var (
	idInit      = strings.Repeat("1", 64)
	idRegular   = strings.Repeat("2", 64)
	idEphemeral = strings.Repeat("3", 64)
	idOther     = strings.Repeat("4", 64)
)

// startIndex runs an index of the pods of lw until the test ends and waits for
// its initial list.
func startIndex(t *testing.T, lw *podindextest.ListerWatcher) *podindex.Index {
	t.Helper()

	idx, err := podindex.New(lw)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup

	wg.Go(func() { idx.Run(ctx) })

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	require.Eventually(t, idx.HasSynced, time.Minute, time.Millisecond)

	return idx
}

func TestContainerIDs(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{Status: corev1.PodStatus{
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: "init", ContainerID: "cri-o://" + idInit},
		},
		ContainerStatuses: []corev1.ContainerStatus{
			{Name: "regular", ContainerID: "containerd://" + idRegular},
			// Still being created.
			{Name: "creating"},
			// Not a container ID of a supported runtime.
			{Name: "invalid", ContainerID: "docker://abc"},
		},
		EphemeralContainerStatuses: []corev1.ContainerStatus{
			{Name: "debug", ContainerID: "containerd://" + idEphemeral},
		},
	}}

	require.Equal(t, []string{idInit, idRegular, idEphemeral}, podindex.ContainerIDs(pod))

	for id, want := range map[string]string{
		idInit:      "init",
		idRegular:   "regular",
		idEphemeral: "debug",
	} {
		name, ok := podindex.ContainerName(pod, id)
		require.True(t, ok)
		require.Equal(t, want, name)
	}

	_, ok := podindex.ContainerName(pod, idOther)
	require.False(t, ok)
}

func TestGetFindsAllContainerKinds(t *testing.T) {
	t.Parallel()

	pod := podindextest.Pod("ns", "pod", "regular", idRegular)
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{
		{Name: "init", ContainerID: "cri-o://" + idInit},
	}
	pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{
		{Name: "debug", ContainerID: "containerd://" + idEphemeral},
	}

	idx := startIndex(t, podindextest.New(*pod))

	for _, id := range []string{idInit, idRegular, idEphemeral} {
		got, ok := idx.Get(id)
		require.True(t, ok, id)
		require.Equal(t, "pod", got.Name)
	}

	_, ok := idx.Get(idOther)
	require.False(t, ok)

	require.Len(t, idx.Pods(), 1)
}

func TestIndexFollowsUpdatesAndDeletions(t *testing.T) {
	t.Parallel()

	creating := podindextest.Pod("ns", "pod", "container", "")
	creating.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubelet"}}

	lw := podindextest.New(*creating)
	idx := startIndex(t, lw)

	_, ok := idx.Get(idRegular)
	require.False(t, ok)

	// The kubelet reports the ID once the container got created.
	running := podindextest.Pod("ns", "pod", "container", idRegular)
	lw.Modify(running)

	require.Eventually(t, func() bool {
		_, ok := idx.Get(idRegular)

		return ok
	}, time.Minute, time.Millisecond)

	pod, _ := idx.Get(idRegular)
	require.Empty(t, pod.ManagedFields)

	// A restarted container gets another ID.
	restarted := podindextest.Pod("ns", "pod", "container", idOther)
	lw.Modify(restarted)

	require.Eventually(t, func() bool {
		_, ok := idx.Get(idOther)

		return ok
	}, time.Minute, time.Millisecond)

	_, ok = idx.Get(idRegular)
	require.False(t, ok)

	lw.Delete(restarted)

	require.Eventually(t, func() bool {
		_, ok := idx.Get(idOther)

		return !ok
	}, time.Minute, time.Millisecond)
	require.Empty(t, idx.Pods())
}

func TestLookupWaitsForContainer(t *testing.T) {
	t.Parallel()

	lw := podindextest.New(
		*podindextest.Pod("ns", "other", "container", idOther),
		*podindextest.Pod("ns", "pod", "container", ""),
	)
	idx := startIndex(t, lw)

	type result struct {
		pod *corev1.Pod
		err error
	}

	done := make(chan result, 1)

	go func() {
		pod, err := idx.Lookup(t.Context(), idRegular)
		done <- result{pod, err}
	}()

	// Unrelated changes do not end the wait.
	lw.Modify(podindextest.Pod("ns", "other", "container", idOther, "sidecar", idEphemeral))

	select {
	case res := <-done:
		require.Failf(t, "lookup returned early", "pod %v, error %v", res.pod, res.err)
	case <-time.After(50 * time.Millisecond):
	}

	lw.Modify(podindextest.Pod("ns", "pod", "container", idRegular))

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.Equal(t, "pod", res.pod.Name)
	case <-time.After(time.Minute):
		require.Fail(t, "lookup did not return")
	}
}

func TestLookupReturnsKnownContainerRightAway(t *testing.T) {
	t.Parallel()

	idx := startIndex(t, podindextest.New(*podindextest.Pod("ns", "pod", "container", idRegular)))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	pod, err := idx.Lookup(ctx, idRegular)
	require.NoError(t, err)
	require.Equal(t, "pod", pod.Name)
}

// A container which no pod of the node is about to start, like one which is
// not managed by Kubernetes, is not waited for.
func TestLookupFailsRightAwayWithoutPendingContainers(t *testing.T) {
	t.Parallel()

	finished := podindextest.Pod("ns", "finished", "container", "")
	finished.Status.Phase = corev1.PodSucceeded

	deleting := podindextest.Pod("ns", "deleting", "container", "")
	deleting.DeletionTimestamp = &metav1.Time{Time: time.Now()}

	idx := startIndex(t, podindextest.New(
		*podindextest.Pod("ns", "pod", "container", idRegular),
		*finished,
		*deleting,
	))

	start := time.Now()
	_, err := idx.Lookup(t.Context(), idOther)
	require.ErrorIs(t, err, podindex.ErrNotFound)
	require.Less(t, time.Since(start), 10*time.Second)
}

// The wait ends once no container is pending anymore, even though the
// deletion of a pod is not signalled as a change.
func TestLookupStopsWaitingWithoutPendingContainers(t *testing.T) {
	t.Parallel()

	creating := podindextest.Pod("ns", "pod", "container", "")
	lw := podindextest.New(*creating)
	idx := startIndex(t, lw)

	done := make(chan error, 1)

	go func() {
		_, err := idx.Lookup(t.Context(), idOther)
		done <- err
	}()

	select {
	case err := <-done:
		require.Failf(t, "lookup returned early", "error %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	lw.Delete(creating)

	select {
	case err := <-done:
		require.ErrorIs(t, err, podindex.ErrNotFound)
	case <-time.After(time.Minute):
		require.Fail(t, "lookup did not return")
	}
}

// blockingListerWatcher holds back the initial list until release is closed,
// so that the index does not sync before.
type blockingListerWatcher struct {
	*podindextest.ListerWatcher

	release chan struct{}
}

//nolint:gocritic // the signature of cache.Lister
func (l *blockingListerWatcher) List(opts metav1.ListOptions) (runtime.Object, error) {
	<-l.release

	return l.ListerWatcher.List(opts)
}

// Before the index synced, it cannot tell whether a pod has the container.
func TestLookupWaitsForSync(t *testing.T) {
	t.Parallel()

	lw := &blockingListerWatcher{
		ListerWatcher: podindextest.New(*podindextest.Pod("ns", "pod", "container", idRegular)),
		release:       make(chan struct{}),
	}

	idx, err := podindex.New(lw)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())

	var wg sync.WaitGroup

	wg.Go(func() { idx.Run(ctx) })

	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	type result struct {
		pod *corev1.Pod
		err error
	}

	done := make(chan result, 1)

	go func() {
		pod, err := idx.Lookup(t.Context(), idRegular)
		done <- result{pod, err}
	}()

	select {
	case res := <-done:
		require.Failf(t, "lookup returned early", "pod %v, error %v", res.pod, res.err)
	case <-time.After(50 * time.Millisecond):
	}

	require.False(t, idx.HasSynced())
	close(lw.release)

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.Equal(t, "pod", res.pod.Name)
	case <-time.After(time.Minute):
		require.Fail(t, "lookup did not return")
	}
}

func TestContainersPending(t *testing.T) {
	t.Parallel()

	running := func() *corev1.Pod {
		pod := podindextest.Pod("ns", "pod", "container", idRegular)
		pod.Status.Phase = corev1.PodRunning

		return pod
	}

	for _, tc := range []struct {
		name   string
		modify func(*corev1.Pod)
		want   bool
	}{
		{name: "running", modify: func(*corev1.Pod) {}},
		{
			name: "without statuses",
			modify: func(pod *corev1.Pod) {
				pod.Status = corev1.PodStatus{Phase: corev1.PodPending}
			},
			want: true,
		},
		{
			name: "container without ID",
			modify: func(pod *corev1.Pod) {
				pod.Status.ContainerStatuses[0].ContainerID = ""
			},
			want: true,
		},
		{
			name: "restart pending",
			modify: func(pod *corev1.Pod) {
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
				}
			},
			want: true,
		},
		{
			name: "exited and restarted",
			modify: func(pod *corev1.Pod) {
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
				}
			},
			want: true,
		},
		{
			name: "failed and restarted on failure",
			modify: func(pod *corev1.Pod) {
				pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 1},
				}
			},
			want: true,
		},
		{
			name: "succeeded and restarted on failure",
			modify: func(pod *corev1.Pod) {
				pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
				}
			},
		},
		{
			name: "exited and never restarted",
			modify: func(pod *corev1.Pod) {
				pod.Spec.RestartPolicy = corev1.RestartPolicyNever
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 1},
				}
			},
		},
		{
			name: "init container completed",
			modify: func(pod *corev1.Pod) {
				pod.Spec.InitContainers = []corev1.Container{{Name: "init"}}
				pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
					Name:        "init",
					ContainerID: "containerd://" + idInit,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
					},
				}}
			},
		},
		{
			name: "sidecar exited",
			modify: func(pod *corev1.Pod) {
				always := corev1.ContainerRestartPolicyAlways
				pod.Spec.InitContainers = []corev1.Container{{Name: "init", RestartPolicy: &always}}
				pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{
					Name:        "init",
					ContainerID: "containerd://" + idInit,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
					},
				}}
			},
			want: true,
		},
		{
			name: "ephemeral container exited",
			modify: func(pod *corev1.Pod) {
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"},
				}}
				pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{
					Name:        "debug",
					ContainerID: "containerd://" + idEphemeral,
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
					},
				}}
			},
		},
		{
			name: "init container not started",
			modify: func(pod *corev1.Pod) {
				pod.Spec.InitContainers = []corev1.Container{{Name: "init"}}
			},
			want: true,
		},
		{
			name: "ephemeral container being added",
			modify: func(pod *corev1.Pod) {
				pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug"},
				}}
			},
			want: true,
		},
		{
			name: "succeeded",
			modify: func(pod *corev1.Pod) {
				pod.Status.Phase = corev1.PodSucceeded
				pod.Status.ContainerStatuses[0].ContainerID = ""
			},
		},
		{
			name: "failed",
			modify: func(pod *corev1.Pod) {
				pod.Status.Phase = corev1.PodFailed
				pod.Status.ContainerStatuses[0].ContainerID = ""
			},
		},
		{
			name: "being deleted",
			modify: func(pod *corev1.Pod) {
				pod.DeletionTimestamp = &metav1.Time{Time: time.Now()}
				pod.Status.ContainerStatuses[0].ContainerID = ""
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pod := running()
			tc.modify(pod)
			require.Equal(t, tc.want, podindex.ContainersPending(pod))
		})
	}
}

func TestLookupTimesOut(t *testing.T) {
	t.Parallel()

	idx := startIndex(t, podindextest.New(*podindextest.Pod("ns", "pod", "container", "")))

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()

	_, err := idx.Lookup(ctx, idRegular)
	require.ErrorIs(t, err, podindex.ErrNotFound)
}

func TestChangedFiresOnAddAndUpdate(t *testing.T) {
	t.Parallel()

	lw := podindextest.New()
	idx := startIndex(t, lw)

	waitClosed := func(ch <-chan struct{}) {
		t.Helper()

		select {
		case <-ch:
		case <-time.After(time.Minute):
			require.Fail(t, "change not signalled")
		}
	}

	changed := idx.Changed()

	lw.Add(podindextest.Pod("ns", "pod", "container", ""))
	waitClosed(changed)

	changed = idx.Changed()

	lw.Modify(podindextest.Pod("ns", "pod", "container", idRegular))
	waitClosed(changed)

	_, ok := idx.Get(idRegular)
	require.True(t, ok, "the pod is indexed once the change is signalled")
}

// TestNewListerWatcherSelectsNode asserts that only the pods of the node are
// listed.
func TestNewListerWatcherSelectsNode(t *testing.T) {
	t.Parallel()

	queries := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case queries <- r.URL.Query().Get("fieldSelector"):
		default:
		}

		w.Header().Set("Content-Type", "application/json")

		if _, err := w.Write(
			[]byte(`{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[]}`),
		); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
	require.NoError(t, err)

	lw := podindex.NewListerWatcher(client, "node-a")

	_, err = lw.ListWithContext(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Equal(t, "spec.nodeName=node-a", <-queries)
}
