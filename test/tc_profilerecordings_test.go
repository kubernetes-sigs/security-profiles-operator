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

	spoutil "sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	exampleRecordingSeccompLogsPath                  = "examples/profilerecording-seccomp-logs.yaml"
	exampleRecordingSeccompSpecificContainerLogsPath = "examples/profilerecording-seccomp-specific-container-logs.yaml"
	exampleRecordingSelinuxLogsPath                  = "examples/profilerecording-selinux-logs.yaml"
	recordingName                                    = "test-recording"
	selinuxRecordingName                             = "test-selinux-recording"
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

func (e *e2e) testCaseProfileRecordingStaticPodLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"syscallName"="listen"`),
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

	pathresult := e.retryGetSelinuxJsonpath("{.spec.allow.http_cache_port_t.tcp_socket}", resourceName)
	e.Contains(pathresult, "name_bind")

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
	e.Contains(profile, "listen")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseProfileRecordingMultiContainerLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingMultiContainer(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"syscallName"="listen"`),
		regexp.MustCompile(`(?m)"container"="redis".*"syscallName"="epoll_wait"`),
	)
}

func (e *e2e) testCaseProfileRecordingSpecificContainerLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingSpecificContainer(exampleRecordingSeccompSpecificContainerLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"syscallName"="epoll_wait"`),
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

	redispathresult := e.retryGetSelinuxJsonpath("{.spec.allow.redis_port_t.tcp_socket}", profileNameRedis)
	e.Contains(redispathresult, "name_bind")

	const profileNameNginx = selinuxRecordingName + "-nginx"
	nginxpathresult := e.retryGetSelinuxJsonpath("{.spec.allow.http_cache_port_t.tcp_socket}", profileNameNginx)
	e.Contains(nginxpathresult, "name_bind")

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

func (e *e2e) profileRecordingSpecificContainer(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for specific container test")
	e.kubectl("create", "-f", recording)

	since, podName := e.createRecordingTestMultiPod()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "pod", podName)

	const profileNameNginx = recordingName + "-nginx"
	profileNginx := e.retryGetSeccompProfile(profileNameNginx)
	e.Contains(profileNginx, "close")

	const profileNameRedis = recordingName + "-redis"
	exists := e.existsSeccompProfile(profileNameRedis)
	e.False(exists)

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", profileNameNginx)
}

func (e *e2e) testCaseProfileRecordingDeploymentLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingDeployment(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="listen"`+
				`.*"container"="nginx".*"syscallName"="listen"`),
	)
}

func (e *e2e) testCaseProfileRecordingDeploymentScaleUpDownLogs() {
	e.logEnricherOnlyTestCase()
	e.profileRecordingScaleDeployment(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="listen"`+
				`.*"container"="nginx".*"syscallName"="listen"`),
	)
}

func (e *e2e) testCaseProfileRecordingSelinuxDeploymentLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()

	e.profileRecordingSelinuxDeployment(
		exampleRecordingSelinuxLogsPath,
		regexp.MustCompile(`(?s)"perm"="listen"`+
			`.*"perm"="listen"`),
	)
}

func (e *e2e) testCaseRecordingFinalizers() {
	e.logEnricherOnlyTestCase()

	const recordingName = "test-recording"

	e.logf("Creating recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingSeccompLogsPath)

	since, podName := e.createRecordingTestPod()
	e.waitForEnricherLogs(since, regexp.MustCompile(`(?m)"syscallName"="listen"`))

	// Check that the recording's status contains the resource. Retry to avoid
	// test races.
	e.logf("Testing that profile binding has pod reference")
	if err := spoutil.Retry(func() error {
		output := e.kubectl("get", "profilerecording", recordingName, "--output", "jsonpath={.status.activeWorkloads[0]}")
		fmt.Println(output)
		if output != podName {
			return fmt.Errorf("pod name %s not found in status", podName)
		}
		return nil
	}, func(err error) bool {
		return true
	}); err != nil {
		e.Fail("failed to find pod name in status")
	}

	// Check that the recording's finalizer is present. Don't retry anymore, the finalizer
	// must be added at this point
	output := e.kubectl("get", "profilerecording", recordingName, "--output", "jsonpath={.metadata.finalizers[0]}")
	e.Equal("active-seccomp-profile-recording-lock", output)

	// Attempt to delete the resource, should not be possible
	e.kubectl("delete", "--wait=false", "profilerecording", recordingName)
	output = e.kubectl("get", "profilerecording", recordingName, "--output", "jsonpath={.metadata.deletionTimestamp}")
	e.NotEmpty(output)

	isDeleted := make(chan bool)
	go func() {
		e.waitFor("delete", "profilerecording", recordingName)
		isDeleted <- true
	}()

	// Delete the pod and check that the resource is removed
	e.kubectl("delete", "pod", podName)

	// Wait a bit for the recording to be actually deleted
	<-isDeleted

	resourceName := recordingName + "-nginx"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")

	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) profileRecordingDeployment(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for deployment test")
	e.kubectl("create", "-f", recording)

	since, deployName := e.createRecordingTestDeployment()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "deploy", deployName)

	const profileName0 = recordingName + "-nginx-0"
	const profileName1 = recordingName + "-nginx-1"
	profile0 := e.retryGetSeccompProfile(profileName0)
	profile1 := e.retryGetSeccompProfile(profileName1)
	e.Contains(profile0, "listen")
	e.Contains(profile1, "listen")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", profileName0, profileName1)
}

func (e *e2e) profileRecordingSelinuxDeployment(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for deployment test")
	e.kubectl("create", "-f", recording)

	since, deployName := e.createRecordingTestDeployment()
	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("delete", "deploy", deployName)

	const profileName0 = selinuxRecordingName + "-nginx-0"
	const profileName1 = selinuxRecordingName + "-nginx-1"

	profile0result := e.retryGetSelinuxJsonpath("{.spec.allow.http_cache_port_t.tcp_socket}", profileName0)
	e.Contains(profile0result, "name_bind")

	profile1result := e.retryGetSelinuxJsonpath("{.spec.allow.http_cache_port_t.tcp_socket}", profileName1)
	e.Contains(profile1result, "name_bind")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "selinuxprofile", profileName0, profileName1)
}

func (e *e2e) createRecordingTestDeployment() (since time.Time, podName string) {
	e.logf("Creating test deployment")
	podName = "my-deployment"

	e.setupRecordingSa(e.getCurrentContextNamespace(defaultNamespace))

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

	testFile, err := os.CreateTemp("", "recording-deployment*.yaml")
	e.Nil(err)
	_, err = testFile.WriteString(testDeployment)
	e.Nil(err)
	err = testFile.Close()
	e.Nil(err)

	since = time.Now()
	e.kubectl("create", "-f", testFile.Name())

	const deployName = "my-deployment"
	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)
	e.Nil(os.Remove(testFile.Name()))

	return since, podName
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

func (e *e2e) retryGetSelinuxJsonpath(jsonpath string, args ...string) string {
	jsonpatharg := fmt.Sprintf("jsonpath=%s", jsonpath)
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
	testPodFile, err := os.CreateTemp("", "recording-pod*.yaml")
	e.Nil(err)
	_, err = testPodFile.WriteString(testPod)
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
	testPodFile, err := os.CreateTemp("", "recording-pod*.yaml")
	e.Nil(err)
	_, err = testPodFile.WriteString(testPod)
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

// tests that scaling the deployment allows to record all replicas
// independent of what happens with the deployment.
func (e *e2e) profileRecordingScaleDeployment(
	recording string, waitConditions ...*regexp.Regexp,
) {
	e.logf("Creating recording for deployment test")
	e.kubectl("create", "-f", recording)

	since, deployName := e.createRecordingTestDeployment()

	if waitConditions != nil {
		e.waitForEnricherLogs(since, waitConditions...)
	}

	e.kubectl("scale", "deploy", "--replicas=5", deployName)
	e.waitFor("condition=available", "deploy", deployName)
	// wait for the pods to be ready as per the readinessProbe
	e.kubectl("rollout", "status", "deploy", deployName)

	e.kubectl("delete", "deploy", deployName)

	// check the expected number of policies was created
	for i := 0; i < 5; i++ {
		recordedProfileName := fmt.Sprintf("%s-nginx-%d", recordingName, i)
		profile := e.retryGetSeccompProfile(recordedProfileName)
		e.Contains(profile, "listen")
		e.kubectl("delete", "sp", recordedProfileName)
	}

	e.kubectl("delete", "-f", recording)
}
