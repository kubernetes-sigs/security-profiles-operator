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
	"io/ioutil"
	"os"
	"regexp"
	"time"
)

const (
	exampleRecordingHookPath        = "examples/profilerecording-hook.yaml"
	exampleRecordingSeccompLogsPath = "examples/profilerecording-seccomp-logs.yaml"
	exampleRecordingSelinuxLogsPath = "examples/profilerecording-selinux-logs.yaml"
	recordingName                   = "test-recording"
	selinuxRecordingName            = "test-selinux-recording"
)

func (e *e2e) waitForEnricherLogs(since time.Time, conditions ...*regexp.Regexp) {
	for i := 0; i < 10; i++ {
		e.logf("Waiting for enricher to record syscalls")
		logs := e.kubectlOperatorNS(
			"logs",
			"--since-time="+since.Format(time.RFC3339),
			"ds/spod",
			"log-enricher",
		)

		matchAll := true
		for _, condition := range conditions {
			if !condition.MatchString(logs) {
				matchAll = false
			}
		}
		if matchAll {
			break
		}

		time.Sleep(3 * time.Second)
	}
}

func (e *e2e) testCaseProfileRecordingStaticPodHook() {
	e.profileRecordingTestCase()
	e.profileRecordingStaticPod(exampleRecordingHookPath)
}

func (e *e2e) testCaseProfileRecordingStaticPodLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"syscallName"="setuid"`),
	)
}

func (e *e2e) testCaseProfileRecordingStaticPodSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	e.profileRecordingStaticSelinuxPod(
		exampleRecordingSelinuxLogsPath,
		regexp.MustCompile(`(?m)"perm"="listen"`),
	)
}

func (e *e2e) profileRecordingStaticSelinuxPod(recording string, waitConditions ...*regexp.Regexp) {
	e.logf("Creating SELinux recording for static pod test")
	e.kubectl("create", "-f", recording)

	since, podName := e.createRecordingTestPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	resourceName := selinuxRecordingName + "-nginx"
	profile := e.retryGetSelinuxProfile(resourceName)
	e.Contains(profile, "(allow process http_port_t ( tcp_socket ( name_bind )))")

	e.kubectl("delete", "-f", recording)

	e.kubectl("delete", "selinuxprofile", resourceName)
}

func (e *e2e) profileRecordingStaticPod(recording string, waitConditions ...*regexp.Regexp) {
	e.logf("Creating recording for static pod test")
	e.kubectl("create", "-f", recording)

	since, podName := e.createRecordingTestPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	resourceName := recordingName + "-nginx"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "setuid")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseProfileRecordingKubectlRunHook() {
	e.profileRecordingTestCase()

	e.logf("Creating recording for kubectl run test")
	e.kubectl("create", "-f", exampleRecordingHookPath)

	e.logf("Creating test pod")
	e.kubectlRun("--labels=app=alpine", "fedora", "--", "echo", "test")

	resourceName := recordingName + "-fedora"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "prctl")
	e.NotContains(profile, "mkdir")

	e.kubectl("delete", "-f", exampleRecordingHookPath)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseProfileRecordingMultiContainerHook() {
	e.profileRecordingTestCase()
	e.profileRecordingMultiContainer(exampleRecordingHookPath)
}

func (e *e2e) testCaseProfileRecordingMultiContainerLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingMultiContainer(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"syscallName"="setuid"`),
		regexp.MustCompile(`(?m)"container"="redis".*"syscallName"="epoll_wait"`),
	)
}

func (e *e2e) testCaseProfileRecordingMultiContainerSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	e.profileRecordingSelinuxMultiContainer(
		exampleRecordingSelinuxLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"perm"="listen"`),
		regexp.MustCompile(`(?m)"container"="redis".*"perm"="name_bind"`),
	)
}

func (e *e2e) profileRecordingSelinuxMultiContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating SELinux recording for multi container test")
	e.kubectl("create", "-f", recording)

	since, podName := e.createRecordingTestMultiPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	const profileNameRedis = selinuxRecordingName + "-redis"
	profileRedis := e.retryGetSelinuxProfile(profileNameRedis)
	e.Contains(profileRedis, "(allow process redis_port_t ( tcp_socket ( name_bind )))")

	const profileNameNginx = selinuxRecordingName + "-nginx"
	profileNginx := e.retryGetSelinuxProfile(profileNameNginx)
	e.Contains(profileNginx, "(allow process http_port_t ( tcp_socket ( name_bind )))")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "selinuxprofile", profileNameRedis, profileNameNginx)
}

func (e *e2e) profileRecordingMultiContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for multi container test")
	e.kubectl("create", "-f", recording)

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

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", profileNameRedis, profileNameNginx)
}

func (e *e2e) testCaseProfileRecordingDeploymentHook() {
	e.profileRecordingTestCase()
	e.profileRecordingDeployment(exampleRecordingHookPath)
}

func (e *e2e) testCaseProfileRecordingDeploymentLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingDeployment(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="setuid"`+
				`.*"container"="nginx".*"syscallName"="setuid"`),
	)
}

func (e *e2e) profileRecordingDeployment(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for deployment test")
	e.kubectl("create", "-f", recording)

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

	if waitConditions != nil {
		since := time.Now()
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "deploy", deployName)

	const profileName0 = recordingName + "-nginx-0"
	const profileName1 = recordingName + "-nginx-1"
	profile0 := e.retryGetSeccompProfile(profileName0)
	profile1 := e.retryGetSeccompProfile(profileName1)
	e.Contains(profile0, "setuid")
	e.Contains(profile1, "setuid")

	e.kubectl("delete", "-f", recording)
	e.Nil(os.Remove(testFile.Name()))
	e.kubectl("delete", "sp", profileName0, profileName1)
}

func (e *e2e) retryGetProfile(kind string, args ...string) string {
	return e.retryGet(append([]string{kind, "-o", "yaml"}, args...)...)
}

func (e *e2e) retryGetSeccompProfile(args ...string) string {
	return e.retryGetProfile("sp", args...)
}

func (e *e2e) retryGetSelinuxProfile(args ...string) string {
	return e.retryGetProfile("selinuxprofile", args...)
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
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-nginx:1.19.1
    name: nginx
  restartPolicy: Never
`
	testPodFile, err := ioutil.TempFile(os.TempDir(), "recording-pod*.yaml")
	e.Nil(err)
	_, err = testPodFile.Write([]byte(testPod))
	e.Nil(err)
	err = testPodFile.Close()
	e.Nil(err)

	since = time.Now()
	e.kubectl("create", "-f", testPodFile.Name())

	e.logf("Waiting for test pod to be initialized")
	e.retryGet("pod", podName)
	e.waitFor("condition=ready", "pod", podName)
	e.Nil(os.Remove(testPodFile.Name()))

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
  containers:
  - name: nginx
    image: quay.io/security-profiles-operator/test-nginx:1.19.1
  - name: redis
    image: quay.io/security-profiles-operator/redis:6.2.1
  restartPolicy: Never
`
	testPodFile, err := ioutil.TempFile(os.TempDir(), "recording-pod*.yaml")
	e.Nil(err)
	_, err = testPodFile.Write([]byte(testPod))
	e.Nil(err)
	err = testPodFile.Close()
	e.Nil(err)

	since = time.Now()
	e.kubectl("create", "-f", testPodFile.Name())

	e.logf("Waiting for test pod to be initialized")
	e.retryGet("pod", podName)
	e.waitFor("condition=ready", "pod", podName)
	e.Nil(os.Remove(testPodFile.Name()))

	return since, podName
}
