//go:build e2e

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

package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	exampleRecordingSeccompLogsPath                  = "examples/profilerecording-seccomp-logs.yaml"
	exampleRecordingSeccompSpecificContainerLogsPath = "examples/profilerecording-seccomp-specific-container-logs.yaml"
	exampleRecordingSelinuxLogsPath                  = "examples/profilerecording-selinux-logs.yaml"
	recordingName                                    = "test-recording"
	selinuxRecordingName                             = "test-selinux-recording"
)

// waitForJsonEnricherLogs waits until the JSON enricher logs since the
// provided time match the conditions, and returns them.
func (e *e2e) waitForJsonEnricherLogs(since time.Time, conditions ...*regexp.Regexp) string {
	// This covers the flush interval of the JSON enricher.
	logs, err := e.pollEnricherContainerLogs(time.Minute, "json-enricher", since, conditions...)
	if err != nil {
		e.Failf("condition not met", "%v", err)
	}

	return logs
}

// waitForJsonEnricherFileLogs waits until the log files of the JSON enricher
// on all nodes match the conditions, and returns their content. The log file
// is only mounted into the JSON enricher, so each spod pod gets a debug
// container with the same mount, which the polls exec into.
func (e *e2e) waitForJsonEnricherFileLogs(logFilePath string, conditions ...*regexp.Regexp) string {
	type volumeMount struct {
		MountPath string `json:"mountPath"`
		Name      string `json:"name"`
	}

	type debugContainer struct {
		VolumeMounts []volumeMount `json:"volumeMounts"`
	}

	customProfile, err := yaml.Marshal(&debugContainer{
		VolumeMounts: []volumeMount{
			{MountPath: filepath.Dir(logFilePath), Name: "json-enricher-log-output-volume"},
		},
	})
	e.Require().NoError(err)

	customProfilePath := filepath.Join(e.T().TempDir(), "custom-profile.yaml")
	e.Require().NoError(os.WriteFile(customProfilePath, customProfile, 0o600))

	podNames := strings.Fields(e.kubectlOperatorNS(
		"get", "pods", "-l", "name=spod", "-o", "jsonpath={.items[*].metadata.name}",
	))
	e.logf("Reading the JSON enricher logs of pods %v", podNames)

	// Ephemeral containers cannot be removed, so every call needs a new name.
	debugContainerName := fmt.Sprintf("json-log-reader-%d", time.Now().Unix())
	for _, podName := range podNames {
		e.kubectlOperatorNS("debug", podName,
			"--image=quay.io/security-profiles-operator/test-nginx:1.19.1",
			"--target=json-enricher", "--custom="+customProfilePath,
			"--container="+debugContainerName, "--", "sleep", "3600")
	}

	var logs string

	// This covers the flush interval of the JSON enricher.
	e.eventually(time.Minute, 10*time.Second, func() error {
		e.logf("Waiting for JSON enricher to record syscalls")

		var logsBuilder strings.Builder

		for _, podName := range podNames {
			podLogs, err := e.kubectlCommand("-n", config.OperatorName, "exec", podName,
				"-c", debugContainerName, "--", "cat", logFilePath)
			if err != nil {
				return fmt.Errorf("reading the JSON enricher logs of pod %s: %w", podName, err)
			}

			logsBuilder.WriteString(podLogs)
		}

		logs = logsBuilder.String()

		return unmatchedLogs(logs, conditions)
	})

	return logs
}

func (e *e2e) waitForEnricherLogs(since time.Time, conditions ...*regexp.Regexp) {
	if err := e.pollEnricherLogs(time.Minute, since, conditions...); err != nil {
		e.Failf("condition not met", "%v", err)
	}
}

// pollEnricherLogs is waitForEnricherLogs, but returns the error instead of
// failing the test.
func (e *e2e) pollEnricherLogs(
	timeout time.Duration, since time.Time, conditions ...*regexp.Regexp,
) error {
	_, err := e.pollEnricherContainerLogs(timeout, "log-enricher", since, conditions...)

	return err
}

// spodContainerLogs returns the logs of the container of all spod pods since
// the provided time. kubectl logs ds/spod reads a single pod, which on a
// cluster with several nodes need not be the one on the node of the workload,
// and with a label selector it reads only the last 10 lines of each pod
// unless --tail says otherwise. The error lets polling callers retry, since
// the logs of a pod which is still starting cannot be read yet.
func (e *e2e) spodContainerLogs(since time.Time, container string) (string, error) {
	return e.kubectlCommand(
		"-n", config.OperatorName,
		"logs",
		"--since-time="+since.Format(time.RFC3339),
		"--tail=-1",
		"-l", "name=spod",
		"-c", container,
	)
}

// pollEnricherContainerLogs polls the logs of the enricher container of the
// spod since the provided time until they match the conditions, and returns
// them, or the error of the last poll once the timeout passes.
func (e *e2e) pollEnricherContainerLogs(
	timeout time.Duration, container string, since time.Time, conditions ...*regexp.Regexp,
) (string, error) {
	var logs string

	err := poll(timeout, 3*time.Second, func() error {
		e.logf("Waiting for the %s to record syscalls", container)

		var err error

		logs, err = e.spodContainerLogs(since, container)
		if err != nil {
			return err
		}

		return unmatchedLogs(logs, conditions)
	})

	return logs, err
}

// enricherLogLine matches a line of the log enricher which has the key and
// value pairs, in the order the enricher logs them.
func enricherLogLine(keysAndValues ...string) *regexp.Regexp {
	pairs := make([]string, 0, len(keysAndValues)/2)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		pairs = append(pairs,
			" "+regexp.QuoteMeta(keysAndValues[i])+`="`+regexp.QuoteMeta(keysAndValues[i+1])+`"`,
		)
	}

	return regexp.MustCompile(`(?m)` + strings.Join(pairs, ".*"))
}

// waitForEnricherLogsOfPods waits for a line of the log enricher with the key
// and value pairs for each pod. A condition matching the lines of any pod
// would be met by the first pod, while the lines of the others are still to
// be processed.
func (e *e2e) waitForEnricherLogsOfPods(
	since time.Time, podNames []string, keysAndValues ...string,
) {
	conditions := make([]*regexp.Regexp, 0, len(podNames))
	for _, podName := range podNames {
		conditions = append(conditions, enricherLogLine(
			append([]string{"pod", podName}, keysAndValues...)...,
		))
	}

	e.waitForEnricherLogs(since, conditions...)
}

func (e *e2e) testCaseProfileRecordingStaticPodLogs() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath, seccompNginx,
		enricherLogLine("syscallName", "listen"),
	)
}

func (e *e2e) testCaseProfileRecordingStaticPodSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticPod(
		exampleRecordingSelinuxLogsPath, selinuxNginx,
		enricherLogLine("perm", "listen"),
	)
}

func (e *e2e) testCaseProfileRecordingStaticPodSELinuxLogsNsNotEnabled() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToNs(nsRecordingDisabled)
	defer restoreNs()

	e.logf("Creating SELinux recording for static pod test")

	e.kubectl("create", "-f", exampleRecordingSelinuxLogsPath)
	e.kubectlCleanup("-f", exampleRecordingSelinuxLogsPath)

	_, podName := e.createRecordingTestPod()
	e.kubectlCleanup("pod", podName)

	output := e.kubectl("get", "pod", "-oyaml", podName)
	e.NotContains(output, "selinuxrecording.process")
}

// recordedNginx is what a recording of the nginx container records, which the
// seccomp and the SELinux recording tests share.
type recordedNginx struct {
	// recording is the name of the recording.
	recording string
	// resource is the resource of the recorded profiles for kubectl.
	resource string
	// check asserts the content of the recorded profile.
	check func(e *e2e, profile string)
}

var (
	seccompNginx = recordedNginx{
		recording: recordingName,
		resource:  "sp",
		check: func(e *e2e, profile string) {
			e.Contains(e.retryGetSeccompProfile(profile), "listen")
		},
	}

	selinuxNginx = recordedNginx{
		recording: selinuxRecordingName,
		resource:  "selinuxprofile",
		check: func(e *e2e, profile string) {
			e.Contains(e.retryGetSelinuxJsonpath(
				"{.spec.allow.http_cache_port_t.tcp_socket}", profile,
			), "name_bind")
		},
	}
)

func (e *e2e) profileRecordingStaticPod(
	recording string, recorded recordedNginx, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating %s recording for static pod test", recorded.resource)
	e.createRecording(recording, recorded.resource, recorded.recording)

	since, podName := e.createRecordingTestPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	resourceName := recorded.recording + "-nginx"
	recorded.check(e, resourceName)
}

// createRecording creates the recording of the manifest, which gets deleted
// together with the profiles it recorded once the current test ends, also if
// it failed. The profiles of a failed test would otherwise make the next one
// fail, since the recordings of the tests share their names.
func (e *e2e) createRecording(manifest, resource, recordingName string) {
	e.kubectl("create", "-f", manifest)
	e.kubectlCleanup("-f", manifest)
	e.cleanupRecordedProfiles(resource, recordingName)
}

// cleanupRecordedProfiles deletes the profiles the recording recorded once
// the current test ends.
func (e *e2e) cleanupRecordedProfiles(resource, recordingName string) {
	e.kubectlCleanup(resource, "-l", profilerecordingapi.ProfileToRecordingLabel+"="+recordingName)
}

func (e *e2e) testCaseProfileRecordingMultiContainerLogs() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingMultiContainer(
		exampleRecordingSeccompLogsPath,
		enricherLogLine("container", "nginx", "syscallName", "listen"),
		enricherLogLine("container", "redis", "syscallName", "epoll_wait"),
	)
}

func (e *e2e) testCaseProfileRecordingSpecificContainerLogs() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingSpecificContainer(exampleRecordingSeccompSpecificContainerLogsPath,
		enricherLogLine("container", "nginx", "syscallName", "epoll_wait"),
	)
}

func (e *e2e) testCaseProfileRecordingMultiContainerSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingSelinuxMultiContainer(
		exampleRecordingSelinuxLogsPath,
		enricherLogLine("container", "nginx", "perm", "listen"),
		enricherLogLine("container", "redis", "perm", "name_bind"),
	)
}

func (e *e2e) profileRecordingSelinuxMultiContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating SELinux recording for multi container test")
	e.createRecording(recording, "selinuxprofile", selinuxRecordingName)

	since, podName := e.createRecordingTestMultiPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	const profileNameRedis = selinuxRecordingName + "-redis"

	redispathresult := e.retryGetSelinuxJsonpath(
		"{.spec.allow.redis_port_t.tcp_socket}",
		profileNameRedis,
	)
	e.Contains(redispathresult, "name_bind")

	const profileNameNginx = selinuxRecordingName + "-nginx"

	nginxpathresult := e.retryGetSelinuxJsonpath(
		"{.spec.allow.http_cache_port_t.tcp_socket}",
		profileNameNginx,
	)
	e.Contains(nginxpathresult, "name_bind")

	// The init container only does what the container policy allows, so it
	// causes no AVCs and the recorder skips its profile. The recorder writes
	// the profiles of the pod one after another, so a wrongly recorded init
	// profile shows up shortly after the other two.
	const profileNameInit = selinuxRecordingName + "-init"

	e.consistently(absentProfileTimeout, defaultPollInterval, func() error {
		if e.existsSelinuxProfile(profileNameInit) {
			return fmt.Errorf("profile %s exists", profileNameInit)
		}

		return nil
	})
}

func (e *e2e) profileRecordingMultiContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for multi container test")
	e.createRecording(recording, "sp", recordingName)

	since, podName := e.createRecordingTestMultiPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	const profileNameRedis = recordingName + "-redis"

	profileRedis := e.retryGetSeccompProfile(profileNameRedis)
	e.Contains(profileRedis, "epoll_wait")

	const profileNameNginx = recordingName + "-nginx"

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	// The log enricher does not reliably attribute the syscalls of the short
	// lived init container while the other containers flood the audit log,
	// so only check that its profile got recorded. The bpf recorder test
	// checks its syscalls.
	const profileNameInit = recordingName + "-init"

	e.NotEmpty(e.retryGetSeccompProfile(profileNameInit))
}

func (e *e2e) profileRecordingSpecificContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for specific container test")
	e.createRecording(recording, "sp", recordingName)

	since, podName := e.createRecordingTestMultiPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	const profileNameNginx = recordingName + "-nginx"

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	// The recorder writes the profiles of the pod one after another, so a
	// wrongly recorded profile of the other containers shows up shortly
	// after the one of nginx.
	e.consistentlyNoSeccompProfiles(recordingName+"-redis", recordingName+"-init")
}

// consistentlyNoSeccompProfiles checks that none of the profiles shows up
// for absentProfileTimeout.
func (e *e2e) consistentlyNoSeccompProfiles(names ...string) {
	e.consistently(absentProfileTimeout, defaultPollInterval, func() error {
		for _, name := range names {
			if e.existsSeccompProfile(name) {
				return fmt.Errorf("profile %s exists", name)
			}
		}

		return nil
	})
}

func (e *e2e) testCaseProfileRecordingDeploymentLogs() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingDeployment(
		exampleRecordingSeccompLogsPath, seccompNginx,
		"container", "nginx", "syscallName", "listen",
	)
}

func (e *e2e) testCaseProfileRecordingDeploymentScaleUpDownLogs() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingScaleDeployment(
		exampleRecordingSeccompLogsPath,
		"container", "nginx", "syscallName", "listen",
	)
}

func (e *e2e) testCaseProfileRecordingSelinuxDeploymentLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingDeployment(
		exampleRecordingSelinuxLogsPath, selinuxNginx,
		"perm", "listen",
	)
}

func (e *e2e) testCaseRecordingFinalizers() {
	e.logEnricherOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating recording for static pod test")
	e.createRecording(exampleRecordingSeccompLogsPath, "sp", recordingName)

	since, podName := e.createRecordingTestPod()
	e.waitForEnricherLogs(since, enricherLogLine("syscallName", "listen"))

	// Check that the recording's status contains the resource. Retry to avoid
	// test races.
	e.logf("Testing that profile binding has pod reference")

	e.eventually(statusUpdateTimeout, time.Second, func() error {
		output := e.kubectl(
			"get",
			"profilerecording",
			recordingName,
			"--output",
			"jsonpath={.status.activeWorkloads[0]}",
		)
		e.logf("Active workloads of the recording: %s", output)

		if output != podName {
			return fmt.Errorf("pod name %s not found in status", podName)
		}

		return nil
	})

	e.eventually(statusUpdateTimeout, time.Second, func() error {
		output := e.kubectl(
			"get",
			"profilerecording",
			recordingName,
			"--output",
			"jsonpath={.metadata.finalizers[0]}",
		)
		if output != "active-seccomp-profile-recording-lock" {
			return fmt.Errorf("finalizer not yet set: %s", output)
		}

		return nil
	})

	// The finalizer keeps the recording while it records the pod.
	e.logf("Deleting the recording while it records a pod")
	e.kubectl("delete", "--wait=false", "profilerecording", recordingName)
	deletionTimestamp := e.kubectl(
		"get", "profilerecording", recordingName,
		"--output", "jsonpath={.metadata.deletionTimestamp}",
	)
	e.NotEmpty(deletionTimestamp, "the recording is not being deleted")

	// Once the pod is gone, the tracker releases the finalizer and the
	// recording goes away, after the profile of the pod got recorded.
	e.kubectl("delete", "pod", podName)
	e.waitFor("delete", "profilerecording", recordingName)

	resourceName := recordingName + "-nginx"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")
}

func (e *e2e) testCaseProfileRecordingWithMemoryOptimization() {
	e.logEnricherOnlyTestCase()

	e.enableMemoryOptimization()
	defer e.disableMemoryOptimization()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath, seccompNginx,
		enricherLogLine("syscallName", "listen"),
	)
}

func (e *e2e) profileRecordingDeployment(
	recording string, recorded recordedNginx, logLine ...string,
) {
	e.logf("Creating %s recording for deployment test", recorded.resource)
	e.createRecording(recording, recorded.resource, recorded.recording)

	since, deployName := e.createRecordingTestDeployment()

	podNames := e.getRecordingPodNames()
	e.Require().Len(podNames, 2, "pods of the recorded deployment")
	e.waitForEnricherLogsOfPods(since, podNames, logLine...)

	suffixes := podSuffixes(podNames)

	e.kubectl("delete", "deploy", deployName)

	for _, sfx := range suffixes {
		recordedProfileName := recorded.recording + "-nginx-" + sfx
		recorded.check(e, recordedProfileName)
	}
}

func (e *e2e) createRecordingTestDeployment() (since time.Time, deployName string) {
	const testDeployment = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  selector:
    matchLabels:
      app: alpine
  replicas: 2
  template:
    metadata:
      labels:
        app: alpine
    spec:
      serviceAccountName: recording-sa
      containers:
      - name: nginx
        image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
        ports:
        - containerPort: 8080
        readinessProbe:
          tcpSocket:
              port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
`

	return e.createRecordingTestDeploymentFromManifest(testDeployment)
}

func (e *e2e) createRecordingTestDeploymentFromManifest(
	manifest string,
) (since time.Time, deployName string) {
	e.logf("Creating test deployment")

	deployName = "my-deployment"

	e.setupRecordingSa(e.getCurrentContextNamespace(defaultNamespace))

	since = time.Now()

	e.writeAndCreate(manifest, "recording-deployment*.yaml")
	e.kubectlCleanup("deploy", deployName)

	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)

	return since, deployName
}

func (e *e2e) retryGetProfile(kind string, args ...string) string {
	return e.retryGet(append([]string{kind, "-o", "yaml"}, args...)...)
}

func (e *e2e) retryGetSeccompProfile(args ...string) string {
	return e.retryGetProfile("sp", args...)
}

func (e *e2e) existsSeccompProfile(args ...string) bool {
	return e.exists(append([]string{"sp"}, args...)...)
}

func (e *e2e) existsSelinuxProfile(args ...string) bool {
	return e.exists(append([]string{"selinuxprofile"}, args...)...)
}

func (e *e2e) retryGetSelinuxJsonpath(jsonpath string, args ...string) string {
	jsonpatharg := "jsonpath=" + jsonpath

	return e.retryGet(append([]string{"selinuxprofile", "-o", jsonpatharg}, args...)...)
}

func (e *e2e) createRecordingTestPod() (since time.Time, podName string) {
	e.logf("Creating test pod")

	podName = "recording"

	const testPod = `
apiVersion: v1
kind: Pod
metadata:
  name: recording
  labels:
    app: alpine
    spo.x-k8s.io/enable-recording: "true"
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    name: nginx
    ports:
      - containerPort: 8080
    readinessProbe:
      tcpSocket:
          port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
  restartPolicy: Never
`

	since = time.Now()

	e.writeAndCreate(testPod, "recording-pod*.yaml")
	e.kubectlCleanup("pod", podName)

	e.logf("Waiting for test pod to be initialized")
	e.retryGet("pod", podName)
	e.waitFor("condition=ready", "pod", podName)

	return since, podName
}

func (e *e2e) createRecordingTestMultiPod() (since time.Time, podName string) {
	e.logf("Creating test pod")

	podName = "my-pod"

	const testPod = `
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  labels:
    app: alpine
spec:
  initContainers:
  - image: quay.io/security-profiles-operator/test-hello-world:latest
    name: init
  containers:
  - name: nginx
    image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
    readinessProbe:
      tcpSocket:
          port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
  - name: redis
    image: quay.io/security-profiles-operator/redis:6.2.1
    readinessProbe:
      tcpSocket:
          port: 6379
      initialDelaySeconds: 5
      periodSeconds: 5
  restartPolicy: Never
`

	since = time.Now()

	e.writeAndCreate(testPod, "recording-pod*.yaml")
	e.kubectlCleanup("pod", podName)

	e.logf("Waiting for test pod to be initialized")
	e.retryGet("pod", podName)
	e.waitFor("condition=ready", "pod", podName)

	return since, podName
}

// tests that scaling the deployment allows to record all replicas
// independent of what happens with the deployment.
func (e *e2e) profileRecordingScaleDeployment(recording string, logLine ...string) {
	e.logf("Creating recording for deployment test")
	e.createRecording(recording, "sp", recordingName)

	since, deployName := e.createRecordingTestDeployment()

	e.waitForEnricherLogsOfPods(since, e.getRecordingPodNames(), logLine...)

	e.kubectl("scale", "deploy", "--replicas=5", deployName)
	e.waitFor("condition=available", "deploy", deployName)
	// wait for the pods to be ready as per the readinessProbe
	e.kubectl("rollout", "status", "deploy", deployName)

	podNames := e.getRecordingPodNames()
	e.Require().Len(podNames, 5, "pods of the scaled up deployment")
	e.waitForEnricherLogsOfPods(since, podNames, logLine...)

	suffixes := podSuffixes(podNames)

	// The profiles of the pods which scaling down deletes get recorded while
	// the deployment still runs.
	e.logf("Scaling the deployment down")
	e.kubectl("scale", "deploy", "--replicas=1", deployName)
	e.eventually(2*time.Minute, defaultPollInterval, func() error {
		recorded := 0

		for _, sfx := range suffixes {
			if e.existsSeccompProfile(recordingName + "-nginx-" + sfx) {
				recorded++
			}
		}

		if want := len(suffixes) - 1; recorded < want {
			return fmt.Errorf("%d of the %d profiles of the deleted pods recorded", recorded, want)
		}

		return nil
	})

	e.kubectl("delete", "deploy", deployName)

	// check the expected number of policies was created
	for _, sfx := range suffixes {
		recordedProfileName := recordingName + "-nginx-" + sfx
		profile := e.retryGetSeccompProfile(recordedProfileName)
		e.Contains(profile, "listen")
	}
}

// getRecordingPodNames returns the names of the recorded test pods, which
// are labeled app=alpine, in the current namespace.
func (e *e2e) getRecordingPodNames() []string {
	return strings.Fields(e.kubectl(
		"get",
		"pods",
		"-l",
		"app=alpine",
		"-o",
		"jsonpath={.items[*].metadata.name}",
	))
}

// podSuffixes returns the random suffixes of the pod names.
func podSuffixes(podNames []string) []string {
	suffixes := make([]string, 0, len(podNames))

	for _, podName := range podNames {
		suffixIdx := strings.LastIndex(podName, "-")
		suffixes = append(suffixes, podName[suffixIdx+1:])
	}

	return suffixes
}
