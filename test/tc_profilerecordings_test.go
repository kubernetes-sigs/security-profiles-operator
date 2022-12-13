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
	"strings"
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
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"syscallName"="listen"`),
	)
}

func (e *e2e) testCaseProfileRecordingStaticPodSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticSelinuxPod(
		exampleRecordingSelinuxLogsPath,
		regexp.MustCompile(`(?m)"perm"="listen"`),
	)
}

func (e *e2e) testCaseProfileRecordingStaticPodSELinuxLogsNsNotEnabled() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()
	restoreNs := e.switchToNs(nsRecordingDisabled)
	defer restoreNs()

	e.logf("Creating SELinux recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingSelinuxLogsPath)
	defer e.kubectl("delete", "-f", exampleRecordingSelinuxLogsPath)

	_, podName := e.createRecordingTestPod()
	defer e.kubectl("delete", "pod", podName)
	output := e.kubectl("get", "pod", "-oyaml", podName)
	e.NotContains(output, "selinuxrecording.process")
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
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()
	e.profileRecordingMultiContainer(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"syscallName"="listen"`),
		regexp.MustCompile(`(?m)"container"="redis".*"syscallName"="epoll_wait"`),
	)
}

func (e *e2e) testCaseProfileRecordingSpecificContainerLogs() {
	e.logEnricherOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()
	e.profileRecordingSpecificContainer(exampleRecordingSeccompSpecificContainerLogsPath,
		regexp.MustCompile(`(?m)"container"="nginx".*"syscallName"="epoll_wait"`),
	)
}

func (e *e2e) testCaseProfileRecordingMultiContainerSELinuxLogs() {
	e.logEnricherOnlyTestCase()
	e.selinuxOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

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

	const profileNameInit = recordingName + "-init"
	exists := e.existsSelinuxProfile(profileNameInit)
	e.False(exists)

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

	const profileNameInit = recordingName + "-init"
	profileInit := e.retryGetSeccompProfile(profileNameInit)
	e.Contains(profileInit, "write")

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", profileNameRedis, profileNameNginx, profileNameInit)
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

	const profileNameInit = recordingName + "-init"
	exists = e.existsSeccompProfile(profileNameInit)
	e.False(exists)

	e.kubectl("delete", "-f", recording)
	e.kubectl("delete", "sp", profileNameNginx)
}

func (e *e2e) testCaseProfileRecordingDeploymentLogs() {
	e.logEnricherOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()
	e.profileRecordingDeployment(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(
			`(?s)"container"="nginx".*"syscallName"="listen"`+
				`.*"container"="nginx".*"syscallName"="listen"`),
	)
}

func (e *e2e) testCaseProfileRecordingDeploymentScaleUpDownLogs() {
	e.logEnricherOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()
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
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingSelinuxDeployment(
		exampleRecordingSelinuxLogsPath,
		regexp.MustCompile(`(?s)"perm"="listen"`+
			`.*"perm"="listen"`),
	)
}

func (e *e2e) testCaseRecordingFinalizers() {
	e.logEnricherOnlyTestCase()
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

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

	// Delete the pod and check that the resource is removed
	e.kubectl("delete", "pod", podName)

	resourceName := recordingName + "-nginx"
	profile := e.retryGetSeccompProfile(resourceName)
	e.Contains(profile, "listen")
	e.kubectl("delete", "-f", exampleRecordingSeccompLogsPath)
	e.kubectl("delete", "sp", resourceName)
}

func (e *e2e) testCaseProfileRecordingWithMemoryOptimization() {
	e.logEnricherOnlyTestCase()
	e.testCaseMemOptmEnable([]string{})
	restoreNs := e.switchToRecordingNs(nsRecordingEnabled)
	defer restoreNs()

	e.profileRecordingStaticPod(
		exampleRecordingSeccompLogsPath,
		regexp.MustCompile(`(?m)"syscallName"="listen"`),
	)
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

	suffixes := e.getPodSuffixesByLabel("app=alpine")
	e.kubectl("delete", "deploy", deployName)

	for _, sfx := range suffixes {
		recordedProfileName := recordingName + "-nginx-" + sfx
		profile := e.retryGetSeccompProfile(recordedProfileName)
		e.Contains(profile, "listen")
		e.kubectl("delete", "sp", recordedProfileName)
	}

	e.kubectl("delete", "-f", recording)
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

	suffixes := e.getPodSuffixesByLabel("app=alpine")
	e.kubectl("delete", "deploy", deployName)

	fmt.Println(e.kubectl("get", "sp"))

	for _, sfx := range suffixes {
		recordedProfileName := selinuxRecordingName + "-nginx-" + sfx
		profileResult := e.retryGetSelinuxJsonpath("{.spec.allow.http_cache_port_t.tcp_socket}", recordedProfileName)
		e.Contains(profileResult, "name_bind")
		e.kubectl("delete", "selinuxprofile", recordedProfileName)
	}

	e.kubectl("delete", "-f", recording)
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

func (e *e2e) createRecordingTestDeploymentFromManifest(manifest string) (since time.Time, deployName string) {
	e.logf("Creating test deployment")
	deployName = "my-deployment"

	e.setupRecordingSa(e.getCurrentContextNamespace(defaultNamespace))

	testFile, err := os.CreateTemp("", "recording-deployment*.yaml")
	e.Nil(err)
	_, err = testFile.WriteString(manifest)
	e.Nil(err)
	err = testFile.Close()
	e.Nil(err)

	since = time.Now()
	e.kubectl("create", "-f", testFile.Name())

	e.retryGet("deploy", deployName)
	e.waitFor("condition=available", "deploy", deployName)
	e.Nil(os.Remove(testFile.Name()))

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

	suffixes := e.getPodSuffixesByLabel("app=alpine")
	e.kubectl("delete", "deploy", deployName)

	// check the expected number of policies was created
	for _, sfx := range suffixes {
		recordedProfileName := recordingName + "-nginx-" + sfx
		profile := e.retryGetSeccompProfile(recordedProfileName)
		e.Contains(profile, "listen")
		e.kubectl("delete", "sp", recordedProfileName)
	}

	e.kubectl("delete", "-f", recording)
}

func (e *e2e) getPodSuffixesByLabel(label string) []string { //nolint:unparam // it's better to keep the param around
	suffixes := make([]string, 0)
	podNamesString := e.kubectl("get", "pods", "-l", label, "-o", "jsonpath={.items[*].metadata.name}")
	podNames := strings.Fields(podNamesString)
	for _, podName := range podNames {
		suffixIdx := strings.LastIndex(podName, "-")
		suffixes = append(suffixes, podName[suffixIdx+1:])
	}

	return suffixes
}
