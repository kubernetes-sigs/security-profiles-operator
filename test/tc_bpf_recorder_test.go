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
	"regexp"
	"time"
)

const (
	exampleRecordingBpfPath                  = "examples/profilerecording-seccomp-bpf.yaml"
	exampleRecordingBpfSpecificContainerPath = "examples/profilerecording-seccomp-bpf-specific-container.yaml"
)

// waitForBpfRecorderLogs waits for the bpf recorder to find the profiles of
// the containers of the recording. The recorder logs the profile annotation of
// the pod, "<recording>_<container>_<nonce>_<timestamp>", not the name of the
// resulting profile.
func (e *e2e) waitForBpfRecorderLogs(since time.Time, containers ...string) {
	patterns := make([]string, 0, len(containers))
	for _, container := range containers {
		patterns = append(patterns,
			`Found profile in cluster for container ID.+profile="`+
				regexp.QuoteMeta(recordingName+"_"+container+"_"))
	}

	e.waitForBpfRecorderLogPatterns(since, patterns)
}

// waitForBpfRecorderPodLogs waits for the bpf recorder to find the profile of
// the container in each of the pods, whose profiles are named after the pod.
func (e *e2e) waitForBpfRecorderPodLogs(
	since time.Time,
	recording, container string,
	pods ...string,
) {
	patterns := make([]string, 0, len(pods))
	for _, pod := range pods {
		patterns = append(patterns,
			`Cache this profile found in cluster.+profile="`+
				regexp.QuoteMeta(recording+"_"+container+"_")+
				`[^"]+".+podName="`+regexp.QuoteMeta(pod)+`"`)
	}

	e.waitForBpfRecorderLogPatterns(since, patterns)
}

func (e *e2e) waitForBpfRecorderLogPatterns(since time.Time, patterns []string) {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		regexes = append(regexes, regexp.MustCompile(pattern))
	}

	// Failing instead of giving up quietly keeps the test from carrying on
	// and failing later with a confusing mismatch.
	e.eventually(45*time.Second, defaultPollInterval, func() error {
		e.logf("Waiting for bpf recorder to start recording %v", patterns)

		logs, err := e.spodContainerLogs(since, "bpf-recorder")
		if err != nil {
			return err
		}

		return unmatchedLogs(logs, regexes)
	})
}

func (e *e2e) testCaseBpfRecorderKubectlRun() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for kubectl run test")
	e.createRecording(exampleRecordingBpfPath, "sp", recordingName)

	e.logf("Creating test pod")
	e.kubectlRun("--labels=app=alpine", "fedora", "--", "sh", "-c", "sleep 20; mkdir /test")

	resourceName := recordingName + "-fedora"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "mkdir")
}

func (e *e2e) testCaseBpfRecorderStaticPod() {
	e.bpfRecorderOnlyTestCase()

	e.bpfRecorderStaticPod()
}

// bpfRecorderStaticPod records a static pod with the bpf recorder and checks
// the recorded profile and the metrics of the recorder.
func (e *e2e) bpfRecorderStaticPod() {
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for static pod test")
	e.createRecording(exampleRecordingBpfPath, "sp", recordingName)

	since, podName := e.createRecordingTestPod()

	resourceName := recordingName + "-nginx"

	e.waitForBpfRecorderLogs(since, "nginx")

	e.kubectl("delete", "pod", podName)

	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	// we don't use resource name here, because the metrics are tracked by the annotation name which contains
	// underscores instead of dashes
	metricName := recordingName + "_nginx"
	bpfMetric := regexp.MustCompile(fmt.Sprintf(
		`(?m)security_profiles_operator_seccomp_profile_bpf_total{`+
			`mount_namespace=".*",`+
			`node=".*",`+
			`profile="%s_.*"} \d+`,
		metricName,
	))

	// The daemon of the node of the pod counts the recorded syscalls.
	e.eventually(metricsTimeout, defaultPollInterval, func() error {
		return unmatchedLogs(e.scrapeSpodMetrics(), []*regexp.Regexp{bpfMetric})
	})
}

func (e *e2e) testCaseBpfRecorderMultiContainer() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for multi container test")
	e.createRecording(exampleRecordingBpfPath, "sp", recordingName)

	since, podName := e.createRecordingTestMultiPod()

	const profileNameRedis = recordingName + "-redis"

	const profileNameNginx = recordingName + "-nginx"

	const profileNameInit = recordingName + "-init"

	e.waitForBpfRecorderLogs(since, "redis", "nginx")

	e.kubectl("delete", "pod", podName)

	profileRedis := e.retryGetSeccompProfile(profileNameRedis)
	e.Contains(profileRedis, "epoll_wait")

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	profileInit := e.retryGetSeccompProfile(profileNameInit)
	e.Contains(profileInit, "write")
}

func (e *e2e) testCaseBpfRecorderDeployment() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for deployment test")
	e.createRecording(exampleRecordingBpfPath, "sp", recordingName)

	// The recorder finds the profiles as soon as the containers start, which
	// is before the deployment is available. The returned time is taken
	// before the deployment gets created.
	since, deployName := e.createRecordingTestDeployment()

	podNames := e.getRecordingPodNames()
	suffixes := podSuffixes(podNames)
	e.Require().Len(suffixes, 2)

	profileName0 := recordingName + "-nginx-" + suffixes[0]
	profileName1 := recordingName + "-nginx-" + suffixes[1]
	e.waitForBpfRecorderPodLogs(since, recordingName, "nginx", podNames...)

	e.kubectl("delete", "deploy", deployName)

	profile0 := e.retryGetSeccompProfile(profileName0)
	profile1 := e.retryGetSeccompProfile(profileName1)
	e.Contains(profile0, "listen")
	e.Contains(profile1, "listen")
}

func (e *e2e) testCaseBpfRecorderParallel() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for parallel test")
	e.createRecording(exampleRecordingBpfPath, "sp", recordingName)

	since, podNames := e.createRecordingTestParallelPods()

	const profileNameFirstCtr = recordingName + "-rec-0"

	const profileNameSecondCtr = recordingName + "-rec-1"

	e.waitForBpfRecorderLogs(since, "rec-0", "rec-1")

	for _, podName := range podNames {
		e.kubectl("delete", "pod", podName)
	}

	firstProfile := e.retryGetSeccompProfile(profileNameFirstCtr)
	e.Contains(firstProfile, "close")

	secondProfile := e.retryGetSeccompProfile(profileNameSecondCtr)
	e.Contains(secondProfile, "epoll_wait")
}

func (e *e2e) createRecordingTestParallelPods() (since time.Time, podNames []string) {
	e.logf("Creating test pod")

	since = time.Now()

	for i, image := range []string{
		"quay.io/security-profiles-operator/test-nginx-unprivileged:1.21",
		"quay.io/security-profiles-operator/redis:6.2.1",
	} {
		podName := fmt.Sprintf("my-pod-%d", i)
		podNames = append(podNames, podName)

		testPod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  labels:
    app: alpine
spec:
  containers:
  - name: rec-%d
    image: %s
  restartPolicy: Never
`, podName, i, image)

		e.writeAndCreate(testPod, "recording-pod*.yaml")
		e.kubectlCleanup("pod", podName)

		e.logf("Waiting for test pod to be initialized")
		e.retryGet("pod", podName)
		e.waitFor("condition=ready", "pod", podName)
	}

	return since, podNames
}

func (e *e2e) testCaseBpfRecorderSelectContainer() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for specific container test")
	e.createRecording(exampleRecordingBpfSpecificContainerPath, "sp", recordingName)

	since, podName := e.createRecordingTestMultiPod()

	const profileNameNginx = recordingName + "-nginx"

	e.waitForBpfRecorderLogs(since, "nginx")

	e.kubectl("delete", "pod", podName)

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "epoll_wait")

	// The recorder writes the profiles of the pod one after another, so a
	// wrongly recorded profile of the other containers shows up shortly
	// after the one of nginx.
	e.consistentlyNoSeccompProfiles(recordingName+"-redis", recordingName+"-init")
}

func (e *e2e) testCaseBpfRecorderWithMemoryOptimization() {
	e.bpfRecorderOnlyTestCase()

	e.enableMemoryOptimization()
	defer e.disableMemoryOptimization()

	e.bpfRecorderStaticPod()
}
