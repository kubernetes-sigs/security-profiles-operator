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
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
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
	// wait for a running reload job is tried again. It is the first delay
	// after a failed reload job as well, which doubles with each further
	// failure up to reloadJobMaxRetryInterval.
	reloadJobRetryInterval = 15 * time.Second

	// reloadJobMaxRetryInterval caps the delay between the reload jobs of a
	// generation which keep failing.
	reloadJobMaxRetryInterval = 15 * time.Minute
)

// errNoPodName is returned if the name of the SPOd pod is unknown.
var errNoPodName = errors.New(config.PodNameEnvKey + " environment variable not set")

// jobFinished returns true if the job completed or failed for good.
func jobFinished(job *batchv1.Job) bool {
	return jobCompleted(job) || jobFailed(job)
}

// jobCompleted returns true if the job reloaded the policy.
func jobCompleted(job *batchv1.Job) bool {
	return hasJobCondition(job, batchv1.JobComplete) || job.Status.Succeeded > 0
}

// jobFailed returns true if the job gave up, because its pods exhausted the
// backoff limit or it ran into its deadline.
func jobFailed(job *batchv1.Job) bool {
	return hasJobCondition(job, batchv1.JobFailed)
}

// hasJobCondition returns true if the condition of the job is true.
func hasJobCondition(job *batchv1.Job, condition batchv1.JobConditionType) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == condition && c.Status == corev1.ConditionTrue {
			return true
		}
	}

	return false
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

// reloadJobState is the outcome of ensuring the reload job of a policy.
type reloadJobState int

const (
	// reloadJobCreated means that a reload job got created.
	reloadJobCreated reloadJobState = iota
	// reloadJobRunning means that the job for the generation exists already
	// and has not finished yet.
	reloadJobRunning
	// reloadJobDone means that the job for the generation completed, so the
	// policy got reloaded.
	reloadJobDone
	// reloadJobFailed means that the job for the generation of an
	// installation failed. It got deleted, so that the next attempt creates a
	// new one.
	reloadJobFailed
	// reloadJobBusy means that a job for another generation is still
	// running, so the reload has to be retried once it finished.
	reloadJobBusy
)

// Labels of the reload jobs.
const (
	reloadJobApp             = "selinux-policy-reload"
	reloadJobLabelApp        = "app"
	reloadJobLabelNode       = "node"
	reloadJobLabelPolicy     = "policy"
	reloadJobLabelAction     = "action"
	reloadJobLabelGeneration = "generation"
	reloadJobLabelProfileUID = "profile-uid"
	reloadJobLabelCreated    = "created"
)

// createPolicyReloadJob creates a short-lived privileged Job to run semodule -R
// on the current node. This is needed because on RHEL 9/OpenShift 4.20+,
// semodule -i no longer automatically reloads the kernel's in-memory policy.
// The job is labeled with the UID and the generation of the profile, so that a
// reconcile which failed to record the reload does not create another job for
// it. The UID keeps a profile which got deleted and recreated with the same
// name, and which starts at the same generation again, from matching a job of
// the old profile. No job is created while a job for another generation is
// still running on the node, which the caller has to retry.
func (r *ReconcileSelinux) createPolicyReloadJob(
	ctx context.Context,
	policyName string,
	kind reloadKind,
	uid types.UID,
	generation int64,
	l logr.Logger,
) (reloadJobState, error) {
	nodeName := r.nodeName
	if nodeName == "" {
		return reloadJobBusy, nodestatus.ErrNoNodeName
	}

	namespace := r.namespace

	// The job runs the selinuxd image of the current pod, which the operator
	// picks per node, and copies what makes the pod run on this node.
	pod, selinuxd, err := r.getSelinuxdPod(ctx, namespace)
	if err != nil {
		return reloadJobBusy, fmt.Errorf("getting selinuxd container: %w", err)
	}

	state, err := r.existingReloadJob(
		ctx,
		namespace,
		nodeName,
		policyName,
		kind,
		uid,
		generation,
		l,
	)
	if err != nil || state != reloadJobCreated {
		return state, err
	}

	job := newReloadJob(
		namespace,
		nodeName,
		policyName,
		kind.action,
		uid,
		generation,
		pod,
		selinuxd,
	)

	l.Info(
		"Creating SELinux policy reload job",
		"nodeName", nodeName,
		"policyName", policyName,
		"profileUID", uid,
		"generation", generation,
	)

	if err := r.client.Create(ctx, job); err != nil {
		return reloadJobBusy, fmt.Errorf("creating reload job: %w", err)
	}

	l.Info("Successfully created SELinux policy reload job", "jobName", job.GetName())

	return reloadJobCreated, nil
}

// existingReloadJob looks for the reload jobs of the policy on the node. If
// one of them is for the generation of the profile with the UID, it returns
// the state of that job, see reloadJobOfGeneration. Otherwise it returns
// reloadJobBusy if another job is still running and reloadJobCreated if a job
// has to be created. A finished job for another generation is no reason to
// skip: it reloaded an older generation.
//
// The jobs are read through the uncached API reader: r.client is backed by a
// cluster-scoped cache, so listing through it would start a cluster-wide Job
// informer, which the namespaced Jobs Role deliberately cannot LIST/WATCH.
// client.InNamespace only filters the cache in memory.
func (r *ReconcileSelinux) existingReloadJob(
	ctx context.Context,
	namespace, nodeName, policyName string,
	kind reloadKind,
	uid types.UID,
	generation int64,
	l logr.Logger,
) (reloadJobState, error) {
	existingJobs := &batchv1.JobList{}
	if err := r.clientReader.List(ctx, existingJobs,
		client.InNamespace(namespace),
		client.MatchingLabels{
			reloadJobLabelApp:    reloadJobApp,
			reloadJobLabelNode:   asLabelValue(nodeName),
			reloadJobLabelPolicy: asLabelValue(policyName),
			reloadJobLabelAction: kind.action,
		}); err != nil {
		return reloadJobBusy, fmt.Errorf("listing existing reload jobs: %w", err)
	}

	wantGeneration := strconv.FormatInt(generation, 10)
	state := reloadJobCreated

	for i := range existingJobs.Items {
		job := &existingJobs.Items[i]
		if job.Labels[reloadJobLabelGeneration] == wantGeneration &&
			job.Labels[reloadJobLabelProfileUID] == string(uid) {
			return r.reloadJobOfGeneration(ctx, job, kind, l)
		}

		if !jobFinished(job) {
			l.Info(
				"Reload job already running for this node, retrying later",
				"existingJob",
				job.Name,
			)

			state = reloadJobBusy
		}
	}

	return state, nil
}

// reloadJobOfGeneration returns the state of the reload job of the generation
// of the profile. A failed job of an installation gets deleted, together with
// its pods, so that the reload can be tried again. A failed job of a removal
// counts as done, see removeReload.
func (r *ReconcileSelinux) reloadJobOfGeneration(
	ctx context.Context,
	job *batchv1.Job,
	kind reloadKind,
	l logr.Logger,
) (reloadJobState, error) {
	switch {
	case jobCompleted(job):
		l.Info("Reload job for this generation completed", "existingJob", job.Name)

		return reloadJobDone, nil
	case jobFailed(job) && !kind.waitForCompletion:
		l.Info("Reload job for this generation failed, not retrying it", "existingJob", job.Name)

		return reloadJobDone, nil
	case jobFailed(job):
		l.Info("Reload job for this generation failed, deleting it", "existingJob", job.Name)

		if err := r.client.Delete(
			ctx, job, client.PropagationPolicy(metav1.DeletePropagationBackground),
		); err != nil && !kerrors.IsNotFound(err) {
			return reloadJobBusy, fmt.Errorf("deleting failed reload job %s: %w", job.Name, err)
		}

		return reloadJobFailed, nil
	default:
		l.Info("Reload job for this generation is still running", "existingJob", job.Name)

		return reloadJobRunning, nil
	}
}

// reloadFailures counts the failed reload jobs of a generation of a profile.
type reloadFailures struct {
	uid        types.UID
	generation int64
	count      int
	// retryAt is when the next job may be created.
	retryAt time.Time
}

// reloadRetryInterval returns the delay after the failures of reload jobs of a
// generation: reloadJobRetryInterval, doubled with each further failure up to
// reloadJobMaxRetryInterval.
func reloadRetryInterval(failures int) time.Duration {
	delay := reloadJobRetryInterval
	for i := 1; i < failures && delay < reloadJobMaxRetryInterval; i++ {
		delay *= 2
	}

	return min(delay, reloadJobMaxRetryInterval)
}

// reloadRetryDelay returns how long the reload of the generation of the
// profile has to wait after its last job failed, or zero if it does not have
// to wait.
func (r *ReconcileSelinux) reloadRetryDelay(
	sp selinuxprofileapi.SelinuxProfileObject, now time.Time,
) time.Duration {
	r.reloadFailuresMu.Lock()
	defer r.reloadFailuresMu.Unlock()

	failures, ok := r.reloadFailures[client.ObjectKeyFromObject(sp)]
	if !ok || failures.uid != sp.GetUID() || failures.generation != sp.GetGeneration() {
		return 0
	}

	return max(failures.retryAt.Sub(now), 0)
}

// recordReloadFailure counts a failed reload job of the generation of the
// profile. It returns the number of failed jobs of the generation and the
// delay until the next one may be created.
func (r *ReconcileSelinux) recordReloadFailure(
	sp selinuxprofileapi.SelinuxProfileObject, now time.Time,
) (int, time.Duration) {
	r.reloadFailuresMu.Lock()
	defer r.reloadFailuresMu.Unlock()

	key := client.ObjectKeyFromObject(sp)

	failures := r.reloadFailures[key]
	if failures.uid != sp.GetUID() || failures.generation != sp.GetGeneration() {
		failures = reloadFailures{uid: sp.GetUID(), generation: sp.GetGeneration()}
	}

	failures.count++
	delay := reloadRetryInterval(failures.count)
	failures.retryAt = now.Add(delay)

	if r.reloadFailures == nil {
		r.reloadFailures = map[types.NamespacedName]reloadFailures{}
	}

	r.reloadFailures[key] = failures

	return failures.count, delay
}

// forgetReloadFailures forgets the failed reload jobs of the profile.
func (r *ReconcileSelinux) forgetReloadFailures(key types.NamespacedName) {
	r.reloadFailuresMu.Lock()
	defer r.reloadFailuresMu.Unlock()

	delete(r.reloadFailures, key)
}

// reloadScript reloads the SELinux policy and reports the result.
const reloadScript = `echo "Reloading SELinux policy..."
semodule -R
exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo "SELinux policy reload successful"
else
    echo "SELinux policy reload failed with exit code $exit_code"
fi
exit $exit_code`

// newReloadJob returns the job which reloads the SELinux policy on the node.
// It runs the selinuxd container of the SPOD pod on the node, with the pull
// policy of that container: the image can be only available locally, and a
// latest tag would default to always pulling.
//
// The job is pinned to the node, which bypasses the scheduler but not the
// admission of the kubelet, which rejects a pod that does not tolerate the
// taints of the node. The SPOD pod runs there, so the job tolerates every
// taint instead of burning its retries, and it gets the priority class and the
// image pull secrets of the SPOD pod. semodule needs no API access, so the
// privileged pod gets no service account token.
func newReloadJob(
	namespace, nodeName, policyName, action string,
	uid types.UID,
	generation int64,
	pod *corev1.Pod,
	selinuxd *corev1.Container,
) *batchv1.Job {
	hostPathDirectory := corev1.HostPathDirectory
	hostPath := func(name, path string) (corev1.Volume, corev1.VolumeMount) {
		volume := corev1.Volume{
			Name: name,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: path, Type: &hostPathDirectory},
			},
		}

		return volume, corev1.VolumeMount{Name: name, MountPath: path}
	}

	fsVolume, fsMount := hostPath("host-fsselinux", "/sys/fs/selinux")
	etcVolume, etcMount := hostPath("host-etcselinux", "/etc/selinux")
	varLibVolume, varLibMount := hostPath("host-varlibselinux", "/var/lib/selinux")

	podLabels := map[string]string{
		reloadJobLabelApp:    reloadJobApp,
		reloadJobLabelNode:   asLabelValue(nodeName),
		reloadJobLabelPolicy: asLabelValue(policyName),
	}

	jobLabels := maps.Clone(podLabels)
	jobLabels[reloadJobLabelAction] = action
	jobLabels[reloadJobLabelGeneration] = strconv.FormatInt(generation, 10)
	jobLabels[reloadJobLabelProfileUID] = string(uid)
	jobLabels[reloadJobLabelCreated] = strconv.FormatInt(time.Now().Unix(), 10)

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: reloadJobNamePrefix,
			Namespace:    namespace,
			Labels:       jobLabels,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: new(reloadJobTTL),
			BackoffLimit:            new(int32(3)),
			ActiveDeadlineSeconds:   new(reloadJobDeadline),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: podLabels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyOnFailure,
					NodeName:                     nodeName,
					ServiceAccountName:           "spod",
					AutomountServiceAccountToken: new(false),
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					PriorityClassName: pod.Spec.PriorityClassName,
					ImagePullSecrets:  slices.Clone(pod.Spec.ImagePullSecrets),
					Containers: []corev1.Container{{
						Name:            "semodule-reload",
						Image:           selinuxd.Image,
						ImagePullPolicy: selinuxd.ImagePullPolicy,
						Command:         []string{"/bin/bash", "-c"},
						Args:            []string{reloadScript},
						VolumeMounts:    []corev1.VolumeMount{fsMount, etcMount, varLibMount},
						SecurityContext: &corev1.SecurityContext{
							Privileged:     new(true),
							SELinuxOptions: &corev1.SELinuxOptions{Type: "spc_t"},
						},
					}},
					Volumes: []corev1.Volume{fsVolume, etcVolume, varLibVolume},
				},
			},
		},
	}
}

// getSelinuxdPod retrieves the current pod and its selinuxd container. This is
// needed because the selinuxd image is set per-node by the operator based on
// the node's OS, so it's not available as an environment variable.
func (r *ReconcileSelinux) getSelinuxdPod(
	ctx context.Context,
	namespace string,
) (*corev1.Pod, *corev1.Container, error) {
	podName := r.podName
	if podName == "" {
		return nil, nil, errNoPodName
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
		return nil, nil, fmt.Errorf("getting pod %s: %w", podName, err)
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == bindata.SelinuxContainerName {
			return pod, &pod.Spec.Containers[i], nil
		}
	}

	return nil, nil, fmt.Errorf("selinuxd container not found in pod %s", podName)
}
