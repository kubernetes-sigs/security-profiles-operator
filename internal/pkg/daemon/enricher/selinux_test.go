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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/podindex/podindextest"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// TestSelinuxSiblingProfiles asserts that the recorded containers of a pod
// which run with the same SELinux options share their AVCs.
func TestSelinuxSiblingProfiles(t *testing.T) {
	t.Parallel()

	recording := &v1.SELinuxOptions{Type: "selinuxrecording.process"}
	recorded := func(name string, options *v1.SELinuxOptions) v1.Container {
		return v1.Container{
			Name:            name,
			SecurityContext: &v1.SecurityContext{SELinuxOptions: options},
		}
	}

	p := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: pod, Namespace: namespace,
			Annotations: map[string]string{
				config.SelinuxProfileRecordLogsAnnotationKey + "init":    "selinux_init_x_1",
				config.SelinuxProfileRecordLogsAnnotationKey + "main":    "selinux_main_x_1",
				config.SelinuxProfileRecordLogsAnnotationKey + "level":   "selinux_level_x_1",
				config.SelinuxProfileRecordLogsAnnotationKey + "foreign": "selinux_main_x_1",
			},
		},
		Spec: v1.PodSpec{
			SecurityContext: &v1.PodSecurityContext{
				SELinuxOptions: &v1.SELinuxOptions{Level: "s0:c1,c2"},
			},
			InitContainers: []v1.Container{recorded("init", recording)},
			Containers: []v1.Container{
				recorded("main", recording),
				// Another level is another context.
				recorded("level", &v1.SELinuxOptions{
					Type: "selinuxrecording.process", Level: "s0:c3,c4",
				}),
				// Not recorded, with the same context.
				recorded("plain", recording),
				// A value which names another container is not recorded.
				recorded("foreign", recording),
			},
		},
	}

	siblings := func(name string) map[string]string {
		options, found := selinuxOptionsOf(p, name)
		if !found {
			return nil
		}

		return selinuxSiblingProfiles(p, name, options)
	}

	require.Equal(t, map[string]string{"init": "selinux_init_x_1"}, siblings("main"))
	require.Equal(t, map[string]string{"main": "selinux_main_x_1"}, siblings("init"))
	require.Nil(t, siblings("level"))
	require.Nil(t, siblings("missing"))
}

// TestDispatchSelinuxLineSiblings asserts that an AVC of a container is
// recorded for the containers of its pod with the same context as well, whose
// denial the kernel does not log again, also before they start, but not for
// one which cannot run any more, like an init container which finished.
func TestDispatchSelinuxLineSiblings(t *testing.T) {
	t.Parallel()

	const thirdContainerID = "f2e5d2ecd4c6e0b5f0f3a7a6b2d9a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"

	recording := &v1.SecurityContext{
		SELinuxOptions: &v1.SELinuxOptions{Type: "selinuxrecording.process"},
	}
	container := func(name string) v1.Container {
		return v1.Container{Name: name, SecurityContext: recording}
	}
	status := func(name, id string, state v1.ContainerState) v1.ContainerStatus {
		if id != "" {
			id = crioPrefix + id
		}

		return v1.ContainerStatus{Name: name, ContainerID: id, State: state}
	}
	running := v1.ContainerState{Running: &v1.ContainerStateRunning{}}
	waiting := v1.ContainerState{Waiting: &v1.ContainerStateWaiting{Reason: "PodInitializing"}}
	done := v1.ContainerState{Terminated: &v1.ContainerStateTerminated{ExitCode: 0}}

	newPod := func() *v1.Pod {
		return &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: pod, Namespace: namespace, UID: "uid",
				Annotations: map[string]string{
					config.SelinuxProfileRecordLogsAnnotationKey + "init":  "selinux_init_x_1",
					config.SelinuxProfileRecordLogsAnnotationKey + "nginx": "selinux_nginx_x_1",
					config.SelinuxProfileRecordLogsAnnotationKey + "redis": "selinux_redis_x_1",
				},
			},
			Spec: v1.PodSpec{
				InitContainers: []v1.Container{container("init")},
				Containers:     []v1.Container{container("nginx"), container("redis")},
			},
		}
	}

	t.Run("main containers before they start", func(t *testing.T) {
		t.Parallel()

		p := newPod()
		p.Status.Phase = v1.PodPending
		p.Status.InitContainerStatuses = []v1.ContainerStatus{status("init", containerID, running)}
		p.Status.ContainerStatuses = []v1.ContainerStatus{
			status("nginx", "", waiting), status("redis", "", waiting),
		}

		sut, _ := newDispatchSut(t, nil)
		watchPods(t, sut.lookup.containers, podindextest.New(*p))

		info, err := sut.lookup.containers.get(containerID)
		require.NoError(t, err)

		sut.dispatchSelinuxLine(node, selinuxTestLine(), info)

		own, found := sut.avcs.get("selinux_init_x_1", "uid", false)
		require.True(t, found)

		for _, sibling := range []string{"selinux_nginx_x_1", "selinux_redis_x_1"} {
			shared, found := sut.avcs.get(sibling, "uid", false)
			require.True(t, found, sibling)
			require.ElementsMatch(t, own, shared)
		}

		// Collecting the profile of the sibling drops what got shared with it.
		_, found = sut.avcs.get("selinux_nginx_x_1", "uid", true)
		require.True(t, found)
		sut.avcs.reset("selinux_nginx_x_1", "uid")

		_, found = sut.avcs.get("selinux_nginx_x_1", "uid", false)
		require.False(t, found)
	})

	t.Run("init container which finished", func(t *testing.T) {
		t.Parallel()

		p := newPod()
		p.Status.Phase = v1.PodRunning
		p.Status.InitContainerStatuses = []v1.ContainerStatus{
			status("init", thirdContainerID, done),
		}
		p.Status.ContainerStatuses = []v1.ContainerStatus{
			status("nginx", containerID, running), status("redis", otherContainerID, running),
		}

		sut, _ := newDispatchSut(t, nil)
		watchPods(t, sut.lookup.containers, podindextest.New(*p))

		info, err := sut.lookup.containers.get(containerID)
		require.NoError(t, err)

		sut.dispatchSelinuxLine(node, selinuxTestLine(), info)

		_, found := sut.avcs.get("selinux_redis_x_1", "uid", false)
		require.True(t, found)

		_, found = sut.avcs.get("selinux_init_x_1", "uid", false)
		require.False(t, found, "the init container cannot need the AVCs any more")
	})
}

// TestContainerMayRun asserts which containers of a pod can still run.
func TestContainerMayRun(t *testing.T) {
	t.Parallel()

	always := v1.ContainerRestartPolicyAlways
	terminated := func(exitCode int32) v1.ContainerState {
		return v1.ContainerState{Terminated: &v1.ContainerStateTerminated{ExitCode: exitCode}}
	}

	for name, tc := range map[string]struct {
		pod     func(*v1.Pod)
		name    string
		running string
		want    bool
	}{
		"init container which runs":                     {name: "init", running: "init", want: true},
		"init container while a regular container runs": {name: "init", running: "main"},
		"sidecar while a regular container runs": {
			name: "init", running: "main", want: true,
			pod: func(p *v1.Pod) { p.Spec.InitContainers[0].RestartPolicy = &always },
		},
		"init container which succeeded": {
			name: "init",
			pod: func(p *v1.Pod) {
				p.Status.InitContainerStatuses[0].State = terminated(0)
			},
		},
		"init container which failed and gets restarted": {
			name: "init", want: true,
			pod: func(p *v1.Pod) {
				p.Status.InitContainerStatuses[0].State = terminated(1)
			},
		},
		"init container which failed in a pod which never restarts": {
			name: "init",
			pod: func(p *v1.Pod) {
				p.Spec.RestartPolicy = v1.RestartPolicyNever
				p.Status.InitContainerStatuses[0].State = terminated(1)
			},
		},
		"sidecar which terminated": {
			name: "init", want: true,
			pod: func(p *v1.Pod) {
				p.Spec.InitContainers[0].RestartPolicy = &always
				p.Status.InitContainerStatuses[0].State = terminated(0)
			},
		},
		"container which did not start yet": {name: "main", want: true},
		"container which terminated in a pod which restarts it": {
			name: "main", want: true,
			pod: func(p *v1.Pod) {
				p.Status.ContainerStatuses = []v1.ContainerStatus{{Name: "main", State: terminated(0)}}
			},
		},
		"container which succeeded in a pod which restarts failed ones": {
			name: "main",
			pod: func(p *v1.Pod) {
				p.Spec.RestartPolicy = v1.RestartPolicyOnFailure
				p.Status.ContainerStatuses = []v1.ContainerStatus{{Name: "main", State: terminated(0)}}
			},
		},
		"container of a finished pod": {
			name: "main",
			pod:  func(p *v1.Pod) { p.Status.Phase = v1.PodFailed },
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := &v1.Pod{
				Spec: v1.PodSpec{
					RestartPolicy:  v1.RestartPolicyAlways,
					InitContainers: []v1.Container{{Name: "init"}},
					Containers:     []v1.Container{{Name: "main"}},
				},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
					InitContainerStatuses: []v1.ContainerStatus{
						{
							Name:  "init",
							State: v1.ContainerState{Running: &v1.ContainerStateRunning{}},
						},
					},
				},
			}
			if tc.pod != nil {
				tc.pod(p)
			}

			require.Equal(t, tc.want, containerMayRun(p, tc.name, tc.running))
		})
	}
}

// selinuxRecordedPod returns a running pod with a container whose SELinux
// profile gets recorded, see runningPod.
func selinuxRecordedPod(name, uid, id string) *v1.Pod {
	p := runningPod()
	p.Name = name
	p.UID = k8stypes.UID(uid)
	p.Annotations = map[string]string{
		config.SelinuxProfileRecordLogsAnnotationKey + "container": "selinux" + uid + "_container_x_1",
	}
	p.Spec.Containers = []v1.Container{{Name: "container"}}
	p.Status.Phase = v1.PodRunning
	p.Status.ContainerStatuses[0].ContainerID = crioPrefix + id

	return p
}

// TestProcessAuditLineSelinuxContextOfExitedProcess asserts that the AVC of a
// process which exited before it got looked up is recorded for the container
// whose AVCs had the same context, as long as its pod runs and records.
func TestProcessAuditLineSelinuxContextOfExitedProcess(t *testing.T) {
	t.Parallel()

	const profile = "selinuxa_container_x_1"

	remembered := &types.ContainerInfo{
		Namespace: namespace, PodUID: "a", ContainerName: "container", ContainerID: containerID,
		SelinuxRecordProfile: profile,
	}

	for name, tc := range map[string]struct {
		lookupErr error
		line      *types.AuditLine
		pod       func(*v1.Pod)
		want      bool
	}{
		"exited process": {
			lookupErr: os.ErrNotExist, line: selinuxTestLine(), want: true,
		},
		"process started after the line": {
			lookupErr: errProcessStartedLater, line: selinuxTestLine(), want: true,
		},
		"recording annotation removed since": {
			lookupErr: os.ErrNotExist, line: selinuxTestLine(),
			pod: func(p *v1.Pod) { p.Annotations = nil },
		},
		"pod finished": {
			lookupErr: os.ErrNotExist, line: selinuxTestLine(),
			pod: func(p *v1.Pod) { p.Status.Phase = v1.PodSucceeded },
		},
		"host process with the PID": {
			lookupErr: util.ErrContainerIDNotFound, line: selinuxTestLine(),
		},
		"other context": {
			lookupErr: os.ErrNotExist,
			line: func() *types.AuditLine {
				line := selinuxTestLine()
				line.Scontext = "system_u:system_r:container_t:s0:c1,c2"

				return line
			}(),
		},
		"seccomp line": {
			lookupErr: os.ErrNotExist,
			line: &types.AuditLine{
				AuditType: types.AuditTypeSeccomp, ProcessID: 42,
				Scontext: selinuxTestLine().Scontext,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := selinuxRecordedPod("a", "a", containerID)
			if tc.pod != nil {
				tc.pod(p)
			}

			sut, mock := newDispatchSut(t, nil)
			watchPods(t, sut.lookup.containers, podindextest.New(*p))
			mock.ContainerIDForPIDReturns("", 0, tc.lookupErr)
			sut.selinuxContexts.remember(selinuxTestLine().Scontext, remembered, time.Now())

			sut.processAuditLine(node, tc.line)

			_, found := sut.avcs.get(profile, "a", false)
			require.Equal(t, tc.want, found)
		})
	}
}

// TestProcessAuditLineSelinuxExplicitLevel asserts that the AVC of an exited
// process is not attributed by a context whose level the pod spec sets, which
// another pod of the node shares without having logged the denial.
func TestProcessAuditLineSelinuxExplicitLevel(t *testing.T) {
	t.Parallel()

	const scontext = "system_u:system_r:selinuxrecording.process:s0:c5,c6"

	recordedPod := func(name, uid, id, level string) *v1.Pod {
		p := runningPod()
		p.Name = name
		p.UID = k8stypes.UID(uid)
		p.Annotations = map[string]string{
			config.SelinuxProfileRecordLogsAnnotationKey + "container": "selinux" + uid + "_container_x_1",
		}
		p.Spec.SecurityContext = &v1.PodSecurityContext{
			SELinuxOptions: &v1.SELinuxOptions{Level: level},
		}
		p.Spec.Containers = []v1.Container{{Name: "container"}}
		p.Status.ContainerStatuses[0].ContainerID = crioPrefix + id

		return p
	}

	for name, level := range map[string]string{
		"level of the runtime": "",
		"explicit level":       "s0:c5,c6",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			a := recordedPod("a", "a", containerID, level)
			b := recordedPod("b", "b", otherContainerID, level)

			sut, mock := newDispatchSut(t, nil)
			watchPods(t, sut.lookup.containers, podindextest.New(*a, *b))

			// Pod a logs the denial, pod b uses the same context.
			mock.ContainerIDForPIDReturnsOnCall(0, containerID, 0, nil)
			mock.ContainerIDForPIDReturns("", 0, os.ErrNotExist)

			first := selinuxTestLine()
			first.Scontext = scontext
			sut.processAuditLine(node, first)

			// A process which exited before it got looked up.
			exited := selinuxTestLine()
			exited.Scontext = scontext
			exited.ProcessID++
			exited.Tclass = "sock_file"
			sut.processAuditLine(node, exited)

			avcs, found := sut.avcs.get("selinuxa_container_x_1", "", false)
			require.True(t, found)

			attributed := false

			for _, avc := range avcs {
				attributed = attributed || strings.Contains(avc, "sock_file")
			}

			require.Equal(t, level == "", attributed)
		})
	}
}

// TestDispatchSelinuxLineRemembersContext asserts that only the contexts of
// recorded containers are remembered for the AVCs of exited processes.
func TestDispatchSelinuxLineRemembersContext(t *testing.T) {
	t.Parallel()

	sut, _ := newDispatchSut(t, nil)
	line := selinuxTestLine()

	sut.dispatchSelinuxLine(node, line, &types.ContainerInfo{Namespace: namespace})

	_, found := sut.selinuxContexts.container(line.Scontext, time.Now())
	require.False(t, found)

	sut.dispatchSelinuxLine(node, line, &types.ContainerInfo{
		Namespace: namespace, SelinuxRecordProfile: "selinux_container_x_1",
	})

	_, found = sut.selinuxContexts.container(line.Scontext, time.Now())
	require.True(t, found)
}

// TestSelinuxContextsOtherUsers asserts that a pod which is not recorded, or
// whose level its spec sets, makes a context ambiguous, and is never the pod
// the AVCs of exited processes get recorded for.
func TestSelinuxContextsOtherUsers(t *testing.T) {
	t.Parallel()

	const scontext = "system_u:system_r:selinuxrecording.process:s0:c1,c2"

	recorded := &types.ContainerInfo{PodUID: "a", SelinuxRecordProfile: "selinuxa_container_x_1"}

	for name, other := range map[string]*types.ContainerInfo{
		"not recorded": {PodUID: "b"},
		"explicit level": {
			PodUID: "b", SelinuxRecordProfile: "selinuxb_container_x_1", SelinuxLevelExplicit: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sut := newSelinuxContexts()
			now := time.Now()

			sut.remember(scontext, other, now)

			_, found := sut.container(scontext, now)
			require.False(t, found, "the only user is not attributable")

			sut.remember(scontext, recorded, now)

			_, found = sut.container(scontext, now)
			require.False(t, found, "the context is ambiguous")
		})
	}
}

// TestSelinuxContextsAmbiguous asserts that a context which several pods use,
// like one with a fixed level, does not attribute the AVCs of exited
// processes to one of them.
func TestSelinuxContextsAmbiguous(t *testing.T) {
	t.Parallel()

	const scontext = "system_u:system_r:selinuxrecording.process:s0:c1,c2"

	pod := func(uid string) *types.ContainerInfo {
		return &types.ContainerInfo{PodUID: uid, SelinuxRecordProfile: "selinux_" + uid + "_x_1"}
	}

	sut := newSelinuxContexts()
	start := time.Now()

	sut.remember(scontext, pod("a"), start)
	sut.remember(scontext, pod("a"), start.Add(time.Minute))

	info, found := sut.container(scontext, start.Add(time.Minute))
	require.True(t, found)
	require.Equal(t, "a", info.PodUID)

	sut.remember(scontext, pod("b"), start.Add(2*time.Minute))

	_, found = sut.container(scontext, start.Add(2*time.Minute))
	require.False(t, found)

	// A third pod keeps the context ambiguous.
	sut.remember(scontext, pod("c"), start.Add(3*time.Minute))

	_, found = sut.container(scontext, start.Add(3*time.Minute))
	require.False(t, found)

	// Once the other pods left the node, the context is the one of the
	// remaining pod.
	sut.sweep(func(uid string) bool { return uid == "c" }, start.Add(4*time.Minute))

	info, found = sut.container(scontext, start.Add(4*time.Minute))
	require.True(t, found)
	require.Equal(t, "c", info.PodUID)

	// A use older than defaultCacheTimeout does not count.
	_, found = sut.container(scontext, start.Add(3*time.Minute+defaultCacheTimeout))
	require.False(t, found)

	sut.sweep(func(string) bool { return true }, start.Add(3*time.Minute+defaultCacheTimeout))
	require.Empty(t, sut.byContext)
}

// TestRecordedDataRefusesNewProfilesWhenFull asserts that a full cache keeps
// the recordings it has, instead of evicting one which is being recorded.
func TestRecordedDataRefusesNewProfilesWhenFull(t *testing.T) {
	t.Parallel()

	sut := newRecordedData()

	for i := range maxCacheItems {
		require.Equal(
			t,
			recorded,
			sut.record(fmt.Sprintf("profile-%d", i), fmt.Sprintf("uid-%d", i), containerID, "read"),
		)
	}

	require.Equal(t, cacheFull, sut.record("new", "uid", containerID, "read"))
	require.Equal(t, stillRefused, sut.record("new", "uid", containerID, "write"))

	// The profiles which are recorded already keep getting recorded.
	first := "profile-0"
	require.Equal(t, recorded, sut.record(first, "uid-0", otherContainerID, "write"))

	items, found := sut.get(first, "uid-0", false)
	require.True(t, found)
	require.ElementsMatch(t, []string{"read", "write"}, items)

	// A collected profile frees its slot. The refused profile stays refused,
	// it would miss what it did before, until its collection found nothing.
	sut.reset(first, "uid-0")
	require.Equal(t, stillRefused, sut.record("new", "uid", containerID, "read"))

	_, found = sut.get("new", "uid", true)
	require.False(t, found)
	sut.reset("new", "uid")

	require.Equal(t, recorded, sut.record("new", "uid", containerID, "read"))
}

// TestRecordedDataRefusedPerPod asserts that the collection for one pod does
// not lift the refusal of the same profile for another pod, whose data is
// missing as well.
func TestRecordedDataRefusedPerPod(t *testing.T) {
	t.Parallel()

	sut := newRecordedData()

	for i := range maxCacheItems {
		require.Equal(
			t,
			recorded,
			sut.record(fmt.Sprintf("profile-%d", i), fmt.Sprintf("uid-%d", i), containerID, "read"),
		)
	}

	require.Equal(t, cacheFull, sut.record("new", "x", containerID, "read"))
	require.Equal(t, cacheFull, sut.record("new", "y", otherContainerID, "read"))

	sut.reset("profile-0", "uid-0")
	sut.reset("new", "y")

	require.Equal(t, stillRefused, sut.record("new", "x", containerID, "read"))
	require.Equal(t, recorded, sut.record("new", "y", otherContainerID, "read"))
}

// TestRecordedDataProfilesPerPod asserts that a pod cannot take up the cache
// with ever new profiles, like by changing its recording annotations.
func TestRecordedDataProfilesPerPod(t *testing.T) {
	t.Parallel()

	sut := newRecordedData()

	for i := range maxProfilesPerPod {
		require.Equal(
			t,
			recorded,
			sut.record(fmt.Sprintf("profile-%d", i), "pod", containerID, "read"),
		)
	}

	require.Equal(t, podLimited, sut.record("one-more", "pod", containerID, "read"))
	require.Equal(t, stillRefused, sut.record("one-more", "pod", containerID, "write"))
	require.Equal(t, stillRefused, sut.record("another-one", "pod", containerID, "read"))

	// The known profiles of the pod and the profiles of other pods still get
	// recorded.
	require.Equal(t, recorded, sut.record("profile-0", "pod", otherContainerID, "write"))
	require.Equal(t, recorded, sut.record("other", "other-pod", otherContainerID, "read"))
}

// TestRecordedDataRecordSiblingAfterCollection asserts that the AVCs of a
// sibling are not recorded for a profile which got collected, nothing would
// collect them again while the pod runs.
func TestRecordedDataRecordSiblingAfterCollection(t *testing.T) {
	t.Parallel()

	sut := newRecordedData()

	require.Equal(t, recorded, sut.recordSibling("init", "uid", "pod/uid/init", "read"))
	require.True(t, sut.insert("init", "uid", containerID, "write"))

	items, found := sut.get("init", "uid", true)
	require.True(t, found)
	require.ElementsMatch(t, []string{"read", "write"}, items)
	sut.reset("init", "uid")

	require.Equal(t, alreadyCollected, sut.recordSibling("init", "uid", "pod/uid/init", "open"))

	_, found = sut.get("init", "uid", false)
	require.False(t, found)
}

// TestRecordedDataSweep asserts that the data of pods which left the node is
// dropped once its collection had time to happen.
func TestRecordedDataSweep(t *testing.T) {
	t.Parallel()

	sut := newRecordedData()

	require.True(t, sut.insert("gone", "gone-pod", containerID, "read"))
	require.True(t, sut.insert("shared", "gone-pod", containerID, "read"))
	require.True(t, sut.insert("shared", "running-pod", otherContainerID, "write"))
	require.True(t, sut.insert("running", "running-pod", otherContainerID, "write"))

	present := func(podUID string) bool { return podUID == "running-pod" }
	start := time.Now()

	require.Empty(t, sut.sweep(present, start))
	require.Empty(t, sut.sweep(present, start.Add(30*time.Minute)))

	_, found := sut.get("gone", "gone-pod", false)
	require.True(t, found, "the collection of the pod may still happen")

	require.Equal(t, []string{"gone"}, sut.sweep(present, start.Add(time.Hour)))

	_, found = sut.get("gone", "", false)
	require.False(t, found)

	shared, found := sut.get("shared", "", false)
	require.True(t, found)
	require.Equal(t, []string{"write"}, shared)

	_, found = sut.get("running", "running-pod", false)
	require.True(t, found)

	// A pod which shows up again starts over.
	require.True(t, sut.insert("back", "back-pod", containerID, "read"))
	require.Empty(t, sut.sweep(present, start.Add(2*time.Hour)))
	require.Empty(t, sut.sweep(func(string) bool { return true }, start.Add(3*time.Hour)))
	require.Empty(t, sut.sweep(present, start.Add(4*time.Hour)))

	_, found = sut.get("back", "back-pod", false)
	require.True(t, found)
}

// TestSweepRecordingsFinishedPods asserts that a pod which finished counts as
// gone, its late lines would keep its data otherwise.
func TestSweepRecordingsFinishedPods(t *testing.T) {
	t.Parallel()

	const scontext = "system_u:system_r:selinuxrecording.process:s0:c1,c2"

	running := runningPod()
	running.UID = "running"
	running.Status.Phase = v1.PodRunning

	finished := runningPod()
	finished.Name = "finished"
	finished.UID = "finished"
	finished.Status.Phase = v1.PodSucceeded
	finished.Status.ContainerStatuses[0].ContainerID = crioPrefix + otherContainerID

	sut, _ := newDispatchSut(t, nil)
	watchPods(t, sut.lookup.containers, podindextest.New(*running, *finished))

	for _, uid := range []string{"running", "finished"} {
		require.True(t, sut.syscalls.insert("profile-"+uid, uid, containerID, "read"))
		sut.selinuxContexts.remember(scontext+uid, &types.ContainerInfo{PodUID: uid}, time.Now())
	}

	sut.sweepRecordings()

	require.Contains(t, sut.syscalls.goneSince, "finished")
	require.NotContains(t, sut.syscalls.goneSince, "running")

	require.NotContains(t, sut.selinuxContexts.byContext, scontext+"finished")
	require.Contains(t, sut.selinuxContexts.byContext, scontext+"running")
}
