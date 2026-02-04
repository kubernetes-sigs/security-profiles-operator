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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

func TestCreatePolicyReloadJob(t *testing.T) {
	t.Parallel()

	// Set up required environment variables
	testNodeName := "test-node-12345"
	testNamespace := "security-profiles-operator"
	testPodName := "spod-test-pod"
	testImage := "registry.example.com/selinuxd:test"
	testAction := "install"

	schemeInstance := scheme.Scheme
	if err := batchv1.AddToScheme(schemeInstance); err != nil {
		t.Fatalf("couldn't add batch API to scheme: %v", err)
	}

	// Create test pod with selinuxd container
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
		existingJobs   []client.Object
		wantErr        bool
		wantJobCreated bool
	}{
		{
			name:           "creates job successfully",
			nodeName:       testNodeName,
			namespace:      testNamespace,
			policyName:     "test-policy",
			existingJobs:   nil,
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			name:       "skips when job already running",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingJobs: []client.Object{
				createTestJob(testNamespace, "existing-job", testNodeName, "test-policy", testAction, 0, 0),
			},
			wantErr:        false,
			wantJobCreated: false, // Should skip
		},
		{
			name:       "creates job when previous job completed long ago",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingJobs: []client.Object{
				createTestJob(testNamespace, "completed-job", testNodeName, "test-policy", testAction, 1, 0),
			},
			wantErr:        false,
			wantJobCreated: true,
		},
		{
			name:       "skips when job was recently created",
			nodeName:   testNodeName,
			namespace:  testNamespace,
			policyName: "test-policy",
			existingJobs: []client.Object{
				createTestJobWithCreationTime(testNamespace, "recent-job", testNodeName, "test-policy", testAction, 1, 0, time.Now().Add(-30*time.Second)),
			},
			wantErr:        false,
			wantJobCreated: false, // Should skip because job was created recently
		},
		{
			name:           "fails when NODE_NAME not set",
			nodeName:       "",
			namespace:      testNamespace,
			policyName:     "test-policy",
			existingJobs:   nil,
			wantErr:        true,
			wantJobCreated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore original env
			origNodeName := os.Getenv(config.NodeNameEnvKey)
			origNamespace := os.Getenv(config.OperatorNamespaceEnvKey)
			origPodName := os.Getenv("POD_NAME")
			defer func() {
				if origNodeName != "" {
					os.Setenv(config.NodeNameEnvKey, origNodeName)
				} else {
					os.Unsetenv(config.NodeNameEnvKey)
				}
				if origNamespace != "" {
					os.Setenv(config.OperatorNamespaceEnvKey, origNamespace)
				} else {
					os.Unsetenv(config.OperatorNamespaceEnvKey)
				}
				if origPodName != "" {
					os.Setenv("POD_NAME", origPodName)
				} else {
					os.Unsetenv("POD_NAME")
				}
			}()

			if tt.nodeName != "" {
				os.Setenv(config.NodeNameEnvKey, tt.nodeName)
				os.Setenv("POD_NAME", testPodName)
			} else {
				os.Unsetenv(config.NodeNameEnvKey)
				os.Unsetenv("POD_NAME")
			}
			os.Setenv(config.OperatorNamespaceEnvKey, tt.namespace)

			// Create fake client with test pod
			var objs []runtime.Object
			objs = append(objs, testPod)
			for _, obj := range tt.existingJobs {
				objs = append(objs, obj.(runtime.Object))
			}
			fakeClient := fake.NewClientBuilder().
				WithScheme(schemeInstance).
				WithRuntimeObjects(objs...).
				Build()

			r := &ReconcileSelinux{
				client: fakeClient,
			}

			logger := logf.Log.WithName("test")
			err := r.createPolicyReloadJob(context.Background(), tt.policyName, testAction, logger)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check if job was created
			jobs := &batchv1.JobList{}
			err = fakeClient.List(context.Background(), jobs)
			require.NoError(t, err)

			if tt.wantJobCreated {
				// Should have at least one new job (plus any existing ones)
				foundNewJob := false
				for _, job := range jobs.Items {
					if strings.HasPrefix(job.Name, reloadJobNamePrefix) &&
						job.Labels["node"] == tt.nodeName &&
						job.Labels["policy"] == tt.policyName {
						foundNewJob = true

						// Verify job spec
						require.Equal(t, tt.nodeName, job.Spec.Template.Spec.NodeName)
						require.Equal(t, "spod", job.Spec.Template.Spec.ServiceAccountName)
						require.Len(t, job.Spec.Template.Spec.Containers, 1)
						require.Equal(t, "semodule-reload", job.Spec.Template.Spec.Containers[0].Name)
						require.Equal(t, testImage, job.Spec.Template.Spec.Containers[0].Image)
						require.True(t, *job.Spec.Template.Spec.Containers[0].SecurityContext.Privileged)
						require.Equal(t, "spc_t", job.Spec.Template.Spec.Containers[0].SecurityContext.SELinuxOptions.Type)
						break
					}
				}
				require.True(t, foundNewJob, "Expected new reload job to be created")
			}
		})
	}
}

func createTestJob(namespace, name, nodeName, policyName, action string, succeeded, failed int32) *batchv1.Job {
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

func createTestJobWithCreationTime(namespace, name, nodeName, policyName, action string, succeeded, failed int32, creationTime time.Time) *batchv1.Job {
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
