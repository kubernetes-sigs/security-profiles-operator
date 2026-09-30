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

package selinuxprofile

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func TestCreatePolicyReloadJob(t *testing.T) {
	t.Parallel()

	testNodeName := "test-node-12345"
	testNamespace := "security-profiles-operator"
	testPodName := "spod-test-pod"
	testImage := "registry.example.com/selinuxd:test"
	testAction := "install"

	schemeInstance := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(schemeInstance))
	require.NoError(t, batchv1.AddToScheme(schemeInstance))

	testPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			PriorityClassName: "system-node-critical",
			ImagePullSecrets:  []corev1.LocalObjectReference{{Name: "pull-secret"}},
			Containers: []corev1.Container{
				{
					Name:  "security-profiles-operator",
					Image: "registry.example.com/spo:test",
				},
				{
					Name:            bindata.SelinuxContainerName,
					Image:           testImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
				},
			},
		},
	}

	tests := []struct {
		name            string
		nodeName        string
		namespace       string
		policyName      string
		existingObjs    []runtime.Object
		podOnlyInReader bool
		wantErr         bool
		wantJobCreated  bool
		wantState       reloadJobState
	}{
		{
			name:           "creates job successfully",
			nodeName:       testNodeName,
			namespace:      testNamespace,
			policyName:     "test-policy",
			existingObjs:   nil,
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			name:            "creates job when current pod is only in client reader",
			nodeName:        testNodeName,
			namespace:       testNamespace,
			policyName:      "test-policy",
			existingObjs:    nil,
			podOnlyInReader: true,
			wantErr:         false,
			wantJobCreated:  true,
		},
		{
			name:       "treats a finished job for the generation as done",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				withGeneration(createTestJob(
					testNamespace, "finished-job",
					testNodeName, "test-policy", testAction, 1, 0,
				), testGeneration),
			},
			wantState: reloadJobExists,
		},
		{
			name:       "treats a running job for the generation as done",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				withGeneration(createTestJob(
					testNamespace, "running-job",
					testNodeName, "test-policy", testAction, 0, 0,
				), testGeneration),
			},
			wantState: reloadJobExists,
		},
		{
			// A profile which got deleted and recreated within the TTL of
			// the jobs starts at the same generation again.
			name:       "creates job when a finished job reloaded a deleted profile",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				withProfile(createTestJob(
					testNamespace, "deleted-profile-job",
					testNodeName, "test-policy", testAction, 1, 0,
				), "7a6e0f4c-1b2d-4e3f-8a9b-0c1d2e3f4a5b", testGeneration),
			},
			wantJobCreated: true,
		},
		{
			name:       "creates job when a finished job reloaded another generation",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				withGeneration(createTestJob(
					testNamespace, "old-job",
					testNodeName, "test-policy", testAction, 1, 0,
				), testGeneration-1),
			},
			wantJobCreated: true,
		},
		{
			name:       "skips when job already running",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				createTestJob(
					testNamespace, "existing-job",
					testNodeName, "test-policy", testAction, 0, 0,
				),
			},
			wantErr:        false,
			wantJobCreated: false,
			wantState:      reloadJobBusy,
		},
		{
			name:       "creates job when previous job completed long ago",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				createTestJob(
					testNamespace, "completed-job",
					testNodeName, "test-policy", testAction, 1, 0,
				),
			},
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			// The callers create one job per generation of the profile, so a
			// recent job reloaded an older generation.
			name:       "creates job when a recent job completed",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				createTestJobWithCreationTime(
					testNamespace, "recent-job",
					testNodeName, "test-policy", testAction,
					1, 0, time.Now().Add(-30*time.Second),
				),
			},
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			name:       "skips when a job is still retrying",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				createTestJob(
					testNamespace, "retrying-job",
					testNodeName, "test-policy", testAction, 0, 1,
				),
			},
			wantErr:        false,
			wantJobCreated: false,
			wantState:      reloadJobBusy,
		},
		{
			name:       "creates job when a previous job failed",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingObjs: []runtime.Object{
				func() runtime.Object {
					job := createTestJob(
						testNamespace, "failed-job",
						testNodeName, "test-policy", testAction, 0, 4,
					)
					job.Status.Conditions = []batchv1.JobCondition{{
						Type:   batchv1.JobFailed,
						Status: corev1.ConditionTrue,
					}}

					return job
				}(),
			},
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			name:           "fails without node name",
			nodeName:       "",
			namespace:      testNamespace,
			policyName:     "test-policy",
			existingObjs:   nil,
			wantErr:        true,
			wantJobCreated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The fake clients set the resource version of the objects they
			// get, which the parallel subtests must not share.
			copies := func(objs ...runtime.Object) []runtime.Object {
				res := make([]runtime.Object, 0, len(objs))

				for _, obj := range objs {
					res = append(res, obj.DeepCopyObject())
				}

				return res
			}

			objs := copies(tt.existingObjs...)
			if !tt.podOnlyInReader {
				objs = append(copies(testPod), objs...)
			}

			// The dedup List goes through the uncached API reader, which in a
			// real cluster serves the same objects as the cached client.
			readerObjs := copies(append([]runtime.Object{testPod}, tt.existingObjs...)...)
			if tt.nodeName == "" {
				readerObjs = nil
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(schemeInstance).
				WithRuntimeObjects(objs...).
				Build()
			fakeClientReader := fake.NewClientBuilder().
				WithScheme(schemeInstance).
				WithRuntimeObjects(readerObjs...).
				Build()

			r := &ReconcileSelinux{
				client:       fakeClient,
				clientReader: fakeClientReader,
				nodeName:     tt.nodeName,
				namespace:    tt.namespace,
				podName:      testPodName,
			}

			logger := logf.Log.WithName("test")
			state, err := r.createPolicyReloadJob(
				context.Background(), tt.policyName, testAction, testUID, testGeneration, logger,
			)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			if tt.wantJobCreated {
				require.Equal(t, reloadJobCreated, state)
			} else {
				require.Equal(t, tt.wantState, state)
			}

			jobs := &batchv1.JobList{}
			err = fakeClient.List(context.Background(), jobs)
			require.NoError(t, err)

			if tt.wantJobCreated {
				foundNewJob := false

				for _, job := range jobs.Items {
					if !strings.HasPrefix(job.Name, reloadJobNamePrefix) ||
						job.Labels["node"] != tt.nodeName ||
						job.Labels["policy"] != tt.policyName {
						continue
					}

					foundNewJob = true

					require.Equal(t, tt.nodeName, job.Spec.Template.Spec.NodeName)
					require.Equal(t, "spod", job.Spec.Template.Spec.ServiceAccountName)
					require.Len(t, job.Spec.Template.Spec.Containers, 1)
					require.Equal(t, "semodule-reload", job.Spec.Template.Spec.Containers[0].Name)
					require.Equal(t, testImage, job.Spec.Template.Spec.Containers[0].Image)
					require.Equal(
						t,
						corev1.PullIfNotPresent,
						job.Spec.Template.Spec.Containers[0].ImagePullPolicy,
					)
					require.True(
						t,
						*job.Spec.Template.Spec.Containers[0].SecurityContext.Privileged,
					)
					require.Equal(t, "spc_t",
						job.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)
					require.Equal(t, "7", job.Labels[reloadJobLabelGeneration])
					require.Equal(t, string(testUID), job.Labels[reloadJobLabelProfileUID])
					require.Equal(
						t,
						"system-node-critical",
						job.Spec.Template.Spec.PriorityClassName,
					)
					require.Equal(
						t,
						testPod.Spec.ImagePullSecrets,
						job.Spec.Template.Spec.ImagePullSecrets,
					)
					require.False(t, *job.Spec.Template.Spec.AutomountServiceAccountToken)
					require.Equal(t,
						[]corev1.Toleration{{Operator: corev1.TolerationOpExists}},
						job.Spec.Template.Spec.Tolerations,
					)

					break
				}

				require.True(t, foundNewJob, "Expected new reload job to be created")
			}
		})
	}
}

func createTestJob(
	namespace, name, nodeName, policyName, action string,
	succeeded, failed int32,
) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app":    "selinux-policy-reload",
				"node":   nodeName,
				"policy": policyName,
				"action": action,
			},
		},
		Status: batchv1.JobStatus{
			Succeeded: succeeded,
			Failed:    failed,
		},
	}
}

// testGeneration is the generation of the profile the tests reload.
const testGeneration = 7

// testUID is the UID of the profile the tests reload.
const testUID = types.UID("0b3c1e2a-5d4f-4a8e-9c61-2f7d8b9a0e11")

// withGeneration labels a reload job with the generation of the test profile
// it reloads.
func withGeneration(job *batchv1.Job, generation int64) *batchv1.Job {
	return withProfile(job, testUID, generation)
}

// withProfile labels a reload job with the UID and the generation of the
// profile it reloads.
func withProfile(job *batchv1.Job, uid types.UID, generation int64) *batchv1.Job {
	job.Labels[reloadJobLabelGeneration] = strconv.FormatInt(generation, 10)
	job.Labels[reloadJobLabelProfileUID] = string(uid)

	return job
}

// newReloadJob is pure, so the job can be checked without a cluster.
func TestNewReloadJob(t *testing.T) {
	t.Parallel()

	pod := &corev1.Pod{Spec: corev1.PodSpec{
		PriorityClassName: "system-node-critical",
		ImagePullSecrets:  []corev1.LocalObjectReference{{Name: "pull-secret"}},
		Tolerations: []corev1.Toleration{{
			Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule,
		}},
	}}
	selinuxd := &corev1.Container{Image: "selinuxd:test", ImagePullPolicy: corev1.PullNever}

	job := newReloadJob("ns", "node-1", "policy", "remove", testUID, 3, pod, selinuxd)

	require.Equal(t, "ns", job.Namespace)
	require.Equal(t, reloadJobNamePrefix, job.GenerateName)
	require.Equal(t, reloadJobApp, job.Labels[reloadJobLabelApp])
	require.Equal(t, "node-1", job.Labels[reloadJobLabelNode])
	require.Equal(t, "policy", job.Labels[reloadJobLabelPolicy])
	require.Equal(t, "remove", job.Labels[reloadJobLabelAction])
	require.Equal(t, "3", job.Labels[reloadJobLabelGeneration])
	require.Equal(t, string(testUID), job.Labels[reloadJobLabelProfileUID])
	require.Empty(t, validation.IsValidLabelValue(job.Labels[reloadJobLabelProfileUID]))
	require.NotEmpty(t, job.Labels[reloadJobLabelCreated])
	require.Equal(t, reloadJobTTL, *job.Spec.TTLSecondsAfterFinished)
	require.Equal(t, reloadJobDeadline, *job.Spec.ActiveDeadlineSeconds)

	spec := job.Spec.Template.Spec
	require.Equal(t, "node-1", spec.NodeName)
	require.Equal(t, "spod", spec.ServiceAccountName)

	// Kubelet admission rejects a pod pinned to a tainted node unless it
	// tolerates the taints, which used to burn the retries of the job.
	require.Equal(t, []corev1.Toleration{{Operator: corev1.TolerationOpExists}}, spec.Tolerations)
	require.Equal(t, "system-node-critical", spec.PriorityClassName)
	require.Equal(t, pod.Spec.ImagePullSecrets, spec.ImagePullSecrets)
	require.False(t, *spec.AutomountServiceAccountToken, "semodule needs no API access")

	require.Len(t, spec.Containers, 1)
	require.Equal(t, "selinuxd:test", spec.Containers[0].Image)
	require.Equal(t, corev1.PullNever, spec.Containers[0].ImagePullPolicy)
	require.True(t, *spec.Containers[0].SecurityContext.Privileged)
	require.Len(t, spec.Volumes, 3)
	require.Len(t, spec.Containers[0].VolumeMounts, 3)

	for i, volume := range spec.Volumes {
		require.Equal(t, volume.Name, spec.Containers[0].VolumeMounts[i].Name)
		require.Equal(t, volume.HostPath.Path, spec.Containers[0].VolumeMounts[i].MountPath)
	}

	// The pull secrets of the pod are not shared with the job.
	job.Spec.Template.Spec.ImagePullSecrets[0].Name = "changed"
	require.Equal(t, "pull-secret", pod.Spec.ImagePullSecrets[0].Name)
}

func createTestJobWithCreationTime(
	namespace, name, nodeName, policyName, action string,
	succeeded, failed int32,
	creationTime time.Time,
) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         namespace,
			CreationTimestamp: metav1.NewTime(creationTime),
			Labels: map[string]string{
				"app":    "selinux-policy-reload",
				"node":   nodeName,
				"policy": policyName,
				"action": action,
			},
		},
		Status: batchv1.JobStatus{
			Succeeded: succeeded,
			Failed:    failed,
		},
	}
}

// Reload jobs of different nodes created in the same second must not collide,
// and their names must be valid whatever the node is called.
func TestCreatePolicyReloadJobNames(t *testing.T) {
	t.Parallel()

	const (
		namespace = "security-profiles-operator"
		podName   = "spod-test-pod"
	)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, batchv1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: namespace},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:  bindata.SelinuxContainerName,
				Image: "registry.example.com/selinuxd:test",
			}}},
		}).
		Build()

	nodes := []string{
		// The first ten characters used to be the same.
		"worker-01.example.com",
		"worker-01.example.org",
		// A name cut after a dot used to end the job name in ".-".
		"worker-01.a",
		strings.Repeat("n", 253),
	}

	for _, node := range nodes {
		r := &ReconcileSelinux{
			client: cli, clientReader: cli, nodeName: node, namespace: namespace, podName: podName,
		}

		state, err := r.createPolicyReloadJob(
			context.Background(), "test-policy", "install", testUID, 1, logf.Log,
		)
		require.NoError(t, err, node)
		require.Equal(t, reloadJobCreated, state, node)
	}

	jobs := &batchv1.JobList{}
	require.NoError(t, cli.List(context.Background(), jobs))
	require.Len(t, jobs.Items, len(nodes))

	for i := range jobs.Items {
		job := &jobs.Items[i]
		require.Empty(t, validation.IsDNS1123Subdomain(job.Name), job.Name)
		require.True(t, strings.HasPrefix(job.Name, reloadJobNamePrefix), job.Name)
		require.NotNil(t, job.Spec.ActiveDeadlineSeconds)
	}
}

func TestAsLabelValue(t *testing.T) {
	t.Parallel()

	// Profile and node names may be up to 253 characters, which the API server
	// rejects as a label value. Without shortening, both the dedup List and the
	// Job create fail validation and policy reloads stop happening on the node.
	const maxLen = 63

	longName := strings.Repeat("a", 253)
	otherLongName := strings.Repeat("a", 252) + "b"

	t.Run("short names are passed through unchanged", func(t *testing.T) {
		t.Parallel()

		for _, name := range []string{
			"",
			"node-1",
			"my.policy_name-1",
			strings.Repeat("a", maxLen),
		} {
			require.Equal(t, name, asLabelValue(name))
		}
	})

	t.Run("long names are shortened to a valid label value", func(t *testing.T) {
		t.Parallel()

		got := asLabelValue(longName)
		require.Len(t, got, maxLen)
		require.True(t, strings.HasPrefix(got, "a"))

		errs := validation.IsValidLabelValue(got)
		require.Empty(t, errs)
	})

	t.Run("names differing only past the cut do not collide", func(t *testing.T) {
		t.Parallel()

		require.NotEqual(t, asLabelValue(longName), asLabelValue(otherLongName))
	})

	t.Run("shortening is deterministic", func(t *testing.T) {
		t.Parallel()

		first := asLabelValue(longName)
		require.Equal(t, first, asLabelValue(longName))
	})
}
