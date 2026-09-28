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
	"regexp"
	"slices"
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

	for range 15 {
		e.logf("Waiting for bpf recorder to start recording %v", patterns)
		logs := e.kubectlOperatorNS(
			"logs",
			"--since-time="+since.Format(time.RFC3339),
			"ds/spod",
			"bpf-recorder",
		)

		if !slices.ContainsFunc(regexes, func(r *regexp.Regexp) bool {
			return !r.MatchString(logs)
		}) {
			return
		}

		time.Sleep(3 * time.Second)
	}

	// Do not return here: giving up quietly lets the test carry on and fail
	// later with a confusing mismatch instead of reporting what actually
	// timed out.
	e.Failf(
		"timed out waiting for the bpf recorder",
		"never logged: %v", patterns,
	)
}

func (e *e2e) testCaseBpfRecorderKubectlRun() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for kubectl run test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	e.logf("Creating test pod")
	e.kubectlRun("--labels=app=alpine", "fedora", "--", "sh", "-c", "sleep 20; mkdir /test")

	resourceName := recordingName + "-fedora"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "mkdir")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseBpfRecorderStaticPod() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	since, podName := e.createRecordingTestPod()

	resourceName := recordingName + "-nginx"

	e.waitForBpfRecorderLogs(since, "nginx")

	e.kubectl("delete", "pod", podName)

	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)

	metrics := e.runAndRetryPodCMD(curlSpodCMD)
	// we don't use resource name here, because the metrics are tracked by the annotation name which contains
	// underscores instead of dashes
	metricName := recordingName + "_nginx"
	e.Regexp(fmt.Sprintf(`(?m)security_profiles_operator_seccomp_profile_bpf_total{`+
		`mount_namespace=".*",`+
		`node=".*",`+
		`profile="%s_.*"} \d+`,
		metricName,
	), metrics)
}

func (e *e2e) testCaseBpfRecorderMultiContainer() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for multi container test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

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

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", profileNameRedis, profileNameNginx, profileNameInit)
}

func (e *e2e) testCaseBpfRecorderDeployment() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for deployment test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	e.logf("Creating test deployment")

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

	testFile, err := os.CreateTemp("", "recording-deployment*.yaml")
	e.Require().NoError(err)
	_, err = testFile.WriteString(testDeployment)
	e.Require().NoError(err)
	err = testFile.Close()
	e.Require().NoError(err)

	// The recorder finds the profiles as soon as the containers start, which
	// is before the deployment is available.
	since := time.Now()

	e.kubectl("create", "-f", testFile.Name())

	const deployName = "my-deployment"

	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)

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

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.Require().NoError(os.Remove(testFile.Name()))
	e.kubectl("delete", "sp", profileName0, profileName1)
}

func (e *e2e) testCaseBpfRecorderParallel() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for parallel test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

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

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", profileNameSecondCtr, profileNameFirstCtr)
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

		testPodFile, err := os.CreateTemp("", "recording-pod*.yaml")
		e.Require().NoError(err)
		_, err = testPodFile.WriteString(testPod)
		e.Require().NoError(err)
		err = testPodFile.Close()
		e.Require().NoError(err)

		e.kubectl("create", "-f", testPodFile.Name())

		e.logf("Waiting for test pod to be initialized")
		e.retryGet("pod", podName)
		e.waitFor("condition=ready", "pod", podName)
		e.NoError(os.Remove(testPodFile.Name()))
	}

	return since, podNames
}

func (e *e2e) testCaseBpfRecorderSelectContainer() {
	e.bpfRecorderOnlyTestCase()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for specific container test")
	e.kubectl("create", "-f", exampleRecordingBpfSpecificContainerPath)

	since, podName := e.createRecordingTestMultiPod()

	const profileNameNginx = recordingName + "-nginx"

	e.waitForBpfRecorderLogs(since, "nginx")

	e.kubectl("delete", "pod", podName)

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "epoll_wait")

	const profileNameRedis = recordingName + "-redis"

	exists := e.existsSeccompProfile(profileNameRedis)
	e.False(exists)

	const profileNameInit = recordingName + "-init"

	exists = e.existsSeccompProfile(profileNameInit)
	e.False(exists)

	e.kubectl("delete", "-f", exampleRecordingBpfSpecificContainerPath)
	e.kubectl("delete", "sp", profileNameNginx)
}

func (e *e2e) testCaseBpfRecorderWithMemoryOptimization() {
	e.bpfRecorderOnlyTestCase()

	e.enableMemoryOptimization()
	defer e.disableMemoryOptimization()

	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.logf("Creating bpf recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	since, podName := e.createRecordingTestPod()

	resourceName := recordingName + "-nginx"

	e.waitForBpfRecorderLogs(since, "nginx")

	e.kubectl("delete", "pod", podName)

	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)

	metrics := e.runAndRetryPodCMD(curlSpodCMD)
	// we don't use resource name here, because the metrics are tracked by the annotation name which contains
	// underscores instead of dashes
	metricName := recordingName + "_nginx"
	e.Regexp(fmt.Sprintf(`(?m)security_profiles_operator_seccomp_profile_bpf_total{`+
		`mount_namespace=".*",`+
		`node=".*",`+
		`profile="%s_.*"} \d+`,
		metricName,
	), metrics)
}
