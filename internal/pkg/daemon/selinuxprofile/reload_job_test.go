/*
Copyright 2026 The Kubernetes Authors.

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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

//nolint:paralleltest,tparallel // subtests modify environment variables and cannot run in parallel
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
			Containers: []corev1.Container{
				{
					Name:  "security-profiles-operator",
					Image: "registry.example.com/spo:test",
				},
				{
					Name:  bindata.SelinuxContainerName,
					Image: testImage,
				},
			},
		},
	}

	tests := []struct {
		name           string
		nodeName       string
		namespace      string
		policyName     string
		existingObjs   []runtime.Object
		wantErr        bool
		wantJobCreated bool
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
			name:       "skips when job was recently created",
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
			wantJobCreated: false,
		},
		{
			name:           "fails when NODE_NAME not set",
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
			t.Setenv(config.NodeNameEnvKey, tt.nodeName)
			t.Setenv(config.OperatorNamespaceEnvKey, tt.namespace)

			if tt.nodeName != "" {
				t.Setenv("POD_NAME", testPodName)
			} else {
				t.Setenv("POD_NAME", "")
			}

			objs := []runtime.Object{testPod}

			for _, obj := range tt.existingObjs {
				objs = append(objs, obj)
			}

			fakeClient := fake.NewClientBuilder().
				WithScheme(schemeInstance).
				WithRuntimeObjects(objs...).
				Build()

			r := &ReconcileSelinux{
				client: fakeClient,
			}

			logger := logf.Log.WithName("test")
			jobCreated, err := r.createPolicyReloadJob(
				context.Background(), tt.policyName, testAction, logger,
			)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantJobCreated, jobCreated)

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
					require.True(t, *job.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)
					require.Equal(t, "spc_t",
						job.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)

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
