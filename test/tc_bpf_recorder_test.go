/*
Copyright 2021 The Kubernetes Authors.

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
	"time"
)

const (
	exampleRecordingBpfPath                  = "examples/profilerecording-seccomp-bpf.yaml"
	exampleRecordingBpfSpecificContainerPath = "examples/profilerecording-seccomp-bpf-specific-container.yaml"
)

func (e *e2e) waitForBpfRecorderLogs(since time.Time, profiles ...string) {
	for i := 0; i < 15; i++ {
		e.logf("Waiting for bpf recorder to start recording profiles %v", profiles)
		logs := e.kubectlOperatorNS(
			"logs",
			"--since-time="+since.Format(time.RFC3339),
			"ds/spod",
			"bpf-recorder",
		)

		matches := 0
		for _, profile := range profiles {
			pattern := fmt.Sprintf(`Found profile in cluster for container ID.+%s`, profile)
			testRegex := regexp.MustCompile(pattern)
			if testRegex.MatchString(logs) {
				matches++
			}
		}
		if matches == len(profiles) {
			return
		}

		time.Sleep(3 * time.Second)
	}
	e.logf("Timeout waiting for bpf recorder to start recording profiles %v", profiles)
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
	e.waitForBpfRecorderLogs(since, resourceName)

	e.kubectl("delete", "pod", podName)

	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)

	metrics := e.getSpodMetrics()
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
	e.waitForBpfRecorderLogs(since, profileNameRedis, profileNameNginx)

	e.kubectl("delete", "pod", podName)

	profileRedis := e.retryGetSeccompProfile(profileNameRedis)
	e.Contains(profileRedis, "epoll_wait")

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", profileNameRedis, profileNameNginx)
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
	e.Nil(err)
	_, err = testFile.WriteString(testDeployment)
	e.Nil(err)
	err = testFile.Close()
	e.Nil(err)

	e.kubectl("create", "-f", testFile.Name())

	const deployName = "my-deployment"
	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)

	suffixes := e.getPodSuffixesByLabel("app=alpine")
	e.Len(suffixes, 2)

	since := time.Now()
	profileName0 := recordingName + "-nginx-" + suffixes[0]
	profileName1 := recordingName + "-nginx-" + suffixes[1]
	e.waitForBpfRecorderLogs(since, profileName0, profileName1)

	e.kubectl("delete", "deploy", deployName)

	profile0 := e.retryGetSeccompProfile(profileName0)
	profile1 := e.retryGetSeccompProfile(profileName1)
	e.Contains(profile0, "listen")
	e.Contains(profile1, "listen")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.Nil(os.Remove(testFile.Name()))
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
	e.waitForBpfRecorderLogs(since, profileNameFirstCtr, profileNameSecondCtr)

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
		e.Nil(err)
		_, err = testPodFile.WriteString(testPod)
		e.Nil(err)
		err = testPodFile.Close()
		e.Nil(err)

		e.kubectl("create", "-f", testPodFile.Name())

		e.logf("Waiting for test pod to be initialized")
		e.retryGet("pod", podName)
		e.waitFor("condition=ready", "pod", podName)
		e.Nil(os.Remove(testPodFile.Name()))
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
	e.waitForBpfRecorderLogs(since, profileNameNginx)

	e.kubectl("delete", "pod", podName)

	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "epoll_wait")

	const profileNameRedis = recordingName + "-redis"
	exists := e.existsSeccompProfile(profileNameRedis)
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
	e.waitForBpfRecorderLogs(since, resourceName)

	e.kubectl("delete", "pod", podName)

	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)

	metrics := e.getSpodMetrics()
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
