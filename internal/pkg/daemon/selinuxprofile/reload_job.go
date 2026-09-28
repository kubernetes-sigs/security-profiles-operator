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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/manager/spod/bindata"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nodestatus"
)

const (
	// reloadJobNamePrefix is the GenerateName of the reload jobs. The API
	// server appends a random suffix, which keeps the names of jobs created
	// at the same time on different nodes apart.
	reloadJobNamePrefix = "selinux-policy-reload-"
	reloadJobTTL        = int32(120) // 2 minutes TTL after completion

	// reloadJobDeadline fails a reload job which does not finish, for example
	// because its pod cannot start, so that it does not block the reloads of
	// the policy forever.
	reloadJobDeadline = int64(600)

	// reloadJobRetryInterval is the time after which a reload which had to
	// wait for a running reload job is tried again.
	reloadJobRetryInterval = 15 * time.Second
)

// jobFinished returns true if the job completed or failed for good.
func jobFinished(job *batchv1.Job) bool {
	for _, c := range job.Status.Conditions {
		if (c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed) &&
			c.Status == corev1.ConditionTrue {
			return true
		}
	}

	return job.Status.Succeeded > 0
}

// maxLabelValueLength is the Kubernetes limit for a label value.
const maxLabelValueLength = 63

// asLabelValue makes an arbitrary name usable as a label value. Profile and node
// names may be up to 253 characters, which the API server rejects as a label
// value, so a long name is shortened and disambiguated with a hash of the
// original. Without this the dedup List and the Job create both fail validation
// and policy reloads silently stop happening on that node.
func asLabelValue(name string) string {
	if len(name) <= maxLabelValueLength {
		return name
	}

	sum := sha256.Sum256([]byte(name))
	suffix := "-" + hex.EncodeToString(sum[:])[:8]

	return name[:maxLabelValueLength-len(suffix)] + suffix
}

// createPolicyReloadJob creates a short-lived privileged Job to run semodule -R
// on the current node. This is needed because on RHEL 9/OpenShift 4.20+,
// semodule -i no longer automatically reloads the kernel's in-memory policy.
// Returns (jobCreated, error) where jobCreated is true if a new job was actually
// created. No job is created while another reload job of the policy is still
// running on the node, which the caller has to retry.
func (r *ReconcileSelinux) createPolicyReloadJob(
	ctx context.Context,
	policyName string,
	action string,
	l logr.Logger,
) (bool, error) {
	nodeName := r.nodeName
	if nodeName == "" {
		return false, nodestatus.ErrNoNodeName
	}

	namespace := config.GetOperatorNamespace()

	// Get the selinuxd image and pull policy from the current pod's selinuxd
	// container. The operator sets the correct per-node image when creating the
	// spod DaemonSet. The pull policy has to match as well: the image can be
	// only available locally, and a latest tag would default to always pulling.
	selinuxd, err := r.getSelinuxdContainerFromPod(ctx, namespace)
	if err != nil {
		return false, fmt.Errorf("getting selinuxd container: %w", err)
	}

	// Check if a reload job of the policy is already running on this node.
	// A finished job is no reason to skip: the callers create a job once per
	// generation of the profile, so a recent job reloaded an older one.
	// Read through the uncached API reader: r.client is backed by a
	// cluster-scoped cache, so listing through it would start a cluster-wide
	// Job informer, which the namespaced Jobs Role deliberately cannot
	// LIST/WATCH. client.InNamespace only filters the cache in memory.
	existingJobs := &batchv1.JobList{}
	if err := r.clientReader.List(ctx, existingJobs,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"app":    "selinux-policy-reload",
			"node":   asLabelValue(nodeName),
			"policy": asLabelValue(policyName),
			"action": action,
		}); err != nil {
		l.Error(err, "Failed to list existing reload jobs")
	} else {
		for i := range existingJobs.Items {
			job := &existingJobs.Items[i]
			if !jobFinished(job) {
				l.Info(
					"Reload job already running for this node, retrying later",
					"existingJob",
					job.Name,
				)

				return false, nil
			}
		}
	}

	privileged := true
	hostPathDirectory := corev1.HostPathDirectory
	backoffLimit := int32(3)
	ttlSeconds := reloadJobTTL
	deadline := reloadJobDeadline

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: reloadJobNamePrefix,
			Namespace:    namespace,
			Labels: map[string]string{
				"app":     "selinux-policy-reload",
				"node":    asLabelValue(nodeName),
				"policy":  asLabelValue(policyName),
				"action":  action,
				"created": strconv.FormatInt(time.Now().Unix(), 10),
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSeconds,
			BackoffLimit:            &backoffLimit,
			ActiveDeadlineSeconds:   &deadline,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":    "selinux-policy-reload",
						"node":   asLabelValue(nodeName),
						"policy": asLabelValue(policyName),
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyOnFailure,
					NodeName:           nodeName,
					ServiceAccountName: "spod",
					Containers: []corev1.Container{
						{
							Name:            "semodule-reload",
							Image:           selinuxd.Image,
							ImagePullPolicy: selinuxd.ImagePullPolicy,
							Command:         []string{"/bin/bash", "-c"},
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

	l.Info(
		"Creating SELinux policy reload job",
		"nodeName",
		nodeName,
		"policyName",
		policyName,
	)

	if err := r.client.Create(ctx, job); err != nil {
		return false, fmt.Errorf("creating reload job: %w", err)
	}

	l.Info("Successfully created SELinux policy reload job", "jobName", job.GetName())

	return true, nil
}

// getSelinuxdContainerFromPod retrieves the selinuxd container from the current pod.
// This is needed because the selinuxd image is set per-node by the operator based on
// the node's OS, so it's not available as an environment variable.
func (r *ReconcileSelinux) getSelinuxdContainerFromPod(
	ctx context.Context,
	namespace string,
) (*corev1.Container, error) {
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		return nil, errors.New("POD_NAME environment variable not set")
	}

	pod := &corev1.Pod{}
	// The daemon manager can filter the pod cache to recording-enabled pods.
	// Read the current SPOD pod directly so the reload path does not depend on
	// recording labels being present on operator-managed pods.
	if err := r.clientReader.Get(
		ctx,
		types.NamespacedName{Name: podName, Namespace: namespace},
		pod,
	); err != nil {
		return nil, fmt.Errorf("getting pod %s: %w", podName, err)
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == bindata.SelinuxContainerName {
			return &pod.Spec.Containers[i], nil
		}
	}

	return nil, fmt.Errorf("selinuxd container not found in pod %s", podName)
}
