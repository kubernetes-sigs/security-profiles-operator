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
	"io/ioutil"
	"os"
	"regexp"
	"time"
)

const exampleRecordingBpfPath = "examples/profilerecording-seccomp-bpf.yaml"

var testRegex = regexp.MustCompile(`Using short path via tracked mount namespace`)

func (e *e2e) waitForBpfRecorderLogs(since time.Time) {
	for i := 0; i < 10; i++ {
		e.logf("Waiting for bpf recorder to find container")
		logs := e.kubectlOperatorNS(
			"logs",
			"--since-time="+since.Format(time.RFC3339),
			"ds/spod",
			"bpf-recorder",
		)

		if testRegex.MatchString(logs) {
			break
		}

		time.Sleep(3 * time.Second)
	}
}

func (e *e2e) testCaseBpfRecorderKubectlRun() {
	e.bpfRecorderOnlyTestCase()

	e.logf("Creating bpf recording for kubectl run test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	e.logf("Creating test pod")
	e.kubectlRun("--labels=app=alpine", "fedora", "--", "sh", "-c", "sleep 3; mkdir /test")

	resourceName := recordingName + "-fedora"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "mkdir")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseBpfRecorderStaticPod() {
	e.bpfRecorderOnlyTestCase()

	e.logf("Creating bpf recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	since, podName := e.createRecordingTestPod()

	e.waitForBpfRecorderLogs(since)

	e.kubectl("delete", "pod", podName)

	resourceName := recordingName + "-nginx"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "setuid")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", resourceName)

	metrics := e.getSpodMetrics()
	e.Regexp(fmt.Sprintf(`(?m)security_profiles_operator_seccomp_profile_bpf_total{`+
		`mount_namespace=".*",`+
		`node=".*",`+
		`profile="%s-.*"} \d+`,
		resourceName,
	), metrics)
}

func (e *e2e) testCaseBpfRecorderMultiContainer() {
	e.bpfRecorderOnlyTestCase()

	e.logf("Creating bpf recording for multi container test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	since, podName := e.createRecordingTestMultiPod()

	e.waitForBpfRecorderLogs(since)

	e.kubectl("delete", "pod", podName)

	const profileNameRedis = recordingName + "-redis"
	profileRedis := e.retryGetSeccompProfile(profileNameRedis)
	e.Contains(profileRedis, "epoll_wait")

	const profileNameNginx = recordingName + "-nginx"
	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", profileNameRedis, profileNameNginx)
}

func (e *e2e) testCaseBpfRecorderDeployment() {
	e.bpfRecorderOnlyTestCase()

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
        image: quay.io/security-profiles-operator/test-nginx:1.19.1
`
	testFile, err := ioutil.TempFile(os.TempDir(), "recording-deployment*.yaml")
	e.Nil(err)
	_, err = testFile.Write([]byte(testDeployment))
	e.Nil(err)
	err = testFile.Close()
	e.Nil(err)

	e.kubectl("create", "-f", testFile.Name())

	const deployName = "my-deployment"
	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)

	since := time.Now()
	e.waitForBpfRecorderLogs(since)

	e.kubectl("delete", "deploy", deployName)

	const profileName0 = recordingName + "-nginx-0"
	const profileName1 = recordingName + "-nginx-1"
	profile0 := e.retryGetSeccompProfile(profileName0)
	profile1 := e.retryGetSeccompProfile(profileName1)
	e.Contains(profile0, "setuid")
	e.Contains(profile1, "setuid")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.Nil(os.Remove(testFile.Name()))
	e.kubectl("delete", "sp", profileName0, profileName1)
}

func (e *e2e) testCaseBpfRecorderParallel() {
	e.bpfRecorderOnlyTestCase()

	e.logf("Creating bpf recording for parallel test")
	e.kubectl("create", "-f", exampleRecordingBpfPath)

	since, podNames := e.createRecordingTestParallelPods()

	e.waitForBpfRecorderLogs(since)

	logs := e.kubectlOperatorNS(
		"logs", "--since-time="+since.Format(time.RFC3339),
		"ds/spod", "bpf-recorder",
	)
	e.Contains(logs, "bpf recorder already running")

	for _, podName := range podNames {
		e.kubectl("delete", "pod", podName)
	}

	const profileNameFirstCtr = recordingName + "-rec-0"
	firstProfile := e.retryGetSeccompProfile(profileNameFirstCtr)
	e.Contains(firstProfile, "close")

	const profileNameSecondCtr = recordingName + "-rec-1"
	secondProfile := e.retryGetSeccompProfile(profileNameSecondCtr)
	e.Contains(secondProfile, "epoll_wait")

	e.kubectl("delete", "-f", exampleRecordingBpfPath)
	e.kubectl("delete", "sp", profileNameSecondCtr, profileNameFirstCtr)
}

func (e *e2e) createRecordingTestParallelPods() (since time.Time, podNames []string) {
	e.logf("Creating test pod")
	since = time.Now()

	for i, image := range []string{
		"quay.io/security-profiles-operator/test-nginx:1.19.1",
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

		testPodFile, err := ioutil.TempFile(os.TempDir(), "recording-pod*.yaml")
		e.Nil(err)
		_, err = testPodFile.Write([]byte(testPod))
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
