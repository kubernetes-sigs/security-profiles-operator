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
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
)

const (
	reloadJobNamePrefix = "selinux-policy-reload-"
	reloadJobTTL        = int32(120) // 2 minutes TTL after completion
)

// createPolicyReloadJob creates a short-lived privileged Job to run semodule -R
// on the current node. This is needed because on RHEL 9/OpenShift 4.20+,
// semodule -i no longer automatically reloads the kernel's in-memory policy.
// Returns (jobCreated, error) where jobCreated is true if a new job was actually created.
func (r *ReconcileSelinux) createPolicyReloadJob(
	ctx context.Context,
	policyName string,
	action string,
	l logr.Logger,
) (bool, error) {
	nodeName := os.Getenv(config.NodeNameEnvKey)
	if nodeName == "" {
		return false, errors.New("NODE_NAME environment variable not set")
	}

	namespace := config.GetOperatorNamespace()

	// Get the selinuxd image from the current pod's selinuxd container.
	// The operator sets the correct per-node image when creating the spod DaemonSet.
	selinuxdImage, err := r.getSelinuxdImageFromPod(ctx, namespace)
	if err != nil {
		return false, fmt.Errorf("getting selinuxd image: %w", err)
	}

	// Check if a reload job for this node is already running or was recently created
	existingJobs := &batchv1.JobList{}
	if err := r.client.List(ctx, existingJobs,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"app":    "selinux-policy-reload",
			"node":   nodeName,
			"policy": policyName,
			"action": action,
		}); err != nil {
		l.Error(err, "Failed to list existing reload jobs")
	} else {
		now := time.Now()

		for i := range existingJobs.Items {
			job := &existingJobs.Items[i]
			// Skip if a job is currently running
			if job.Status.Succeeded == 0 && job.Status.Failed == 0 {
				l.Info("Reload job already running for this node, skipping", "existingJob", job.Name)

				return false, nil
			}
			// Skip if a job was created recently (within TTL window) to avoid duplicate reloads
			if job.CreationTimestamp.Add(time.Duration(reloadJobTTL) * time.Second).After(now) {
				l.Info("Reload job was recently created for this node, skipping",
					"existingJob", job.Name, "age", now.Sub(job.CreationTimestamp.Time))
				return false, nil
			}
		}
	}

	// Use a unique job name based on timestamp to avoid conflicts
	jobName := fmt.Sprintf("%s%s-%d", reloadJobNamePrefix, nodeName[:min(10, len(nodeName))], time.Now().Unix())

	privileged := true
	hostPathDirectory := corev1.HostPathDirectory
	backoffLimit := int32(3)
	ttlSeconds := reloadJobTTL

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels: map[string]string{
				"app":     "selinux-policy-reload",
				"node":    nodeName,
				"policy":  policyName,
				"action":  action,
				"created": strconv.FormatInt(time.Now().Unix(), 10),
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSeconds,
			BackoffLimit:            &backoffLimit,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":    "selinux-policy-reload",
						"node":   nodeName,
						"policy": policyName,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					NodeName:           nodeName,
					ServiceAccountName: "spod",
					Containers: []corev1.Container{
						{
							Name:    "semodule-reload",
							Image:   selinuxdImage,
							Command: []string{"/bin/bash", "-c"},
							Args: []string{
								`echo "Reloading SELinux policy..."
semodule -R
exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo "SELinux policy reload successful"
else
    echo "SELinux policy reload failed with exit code $exit_code"
fi
exit $exit_code`,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "host-fsselinux",
									MountPath: "/sys/fs/selinux",
								},
								{
									Name:      "host-etcselinux",
									MountPath: "/etc/selinux",
								},
								{
									Name:      "host-varlibselinux",
									MountPath: "/var/lib/selinux",
								},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
								SELinuxOptions: &corev1.SELinuxOptions{
									Type: "spc_t",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "host-fsselinux",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys/fs/selinux",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "host-etcselinux",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc/selinux",
									Type: &hostPathDirectory,
								},
							},
						},
						{
							Name: "host-varlibselinux",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/selinux",
									Type: &hostPathDirectory,
								},
							},
						},
					},
				},
			},
		},
	}

	l.Info("Creating SELinux policy reload job", "jobName", jobName, "nodeName", nodeName, "policyName", policyName)

	if err := r.client.Create(ctx, job); err != nil {
		if kerrors.IsAlreadyExists(err) {
			l.Info("Reload job already exists, skipping", "jobName", jobName)
			return false, nil
		}
		return false, fmt.Errorf("creating reload job: %w", err)
	}

	l.Info("Successfully created SELinux policy reload job", "jobName", jobName)

	return true, nil
}

// getSelinuxdImageFromPod retrieves the selinuxd container image from the current pod.
// This is needed because the selinuxd image is set per-node by the operator based on
// the node's OS, so it's not available as an environment variable.
func (r *ReconcileSelinux) getSelinuxdImageFromPod(ctx context.Context, namespace string) (string, error) {
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		return "", errors.New("POD_NAME environment variable not set")
	}

	pod := &corev1.Pod{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: podName, Namespace: namespace}, pod); err != nil {
		return "", fmt.Errorf("getting pod %s: %w", podName, err)
	}

	// Find the selinuxd container and get its image
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == bindata.SelinuxContainerName {
			return pod.Spec.Containers[i].Image, nil
		}
	}

	return "", fmt.Errorf("selinuxd container not found in pod %s", podName)
}
