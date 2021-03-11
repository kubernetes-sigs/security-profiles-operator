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
	"strings"
)

const (
	exampleRecordingPath = "examples/profilerecording.yaml"
	recordingName        = "test-recording"
)

func (e *e2e) testCaseProfileRecordingStaticPod() {
	e.profileRecordingTestCase()

	e.logf("Creating recording for static pod test")
	e.kubectl("create", "-f", exampleRecordingPath)
	defer e.kubectl("delete", "-f", exampleRecordingPath)

	e.logf("Creating test pod")
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
	defer os.Remove(testPodFile.Name())
	_, err = testPodFile.Write([]byte(testPod))
	e.Nil(err)
	err = testPodFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", testPodFile.Name())

	e.logf("Waiting for test pod to be initialized")
	e.waitFor("condition=ready", "pod", "recording")
	e.kubectl("delete", "pod", "recording")

	resourceName := recordingName + "-nginx"
	profile := e.kubectl("get", "sp", resourceName, "-o", "yaml")
	defer e.kubectl("delete", "sp", resourceName)
	e.Contains(profile, "mkdir")
}

func (e *e2e) testCaseProfileRecordingKubectlRun() {
	e.profileRecordingTestCase()

	e.logf("Creating recording for kubectl run test")
	e.kubectl("create", "-f", exampleRecordingPath)
	defer e.kubectl("delete", "-f", exampleRecordingPath)

	e.logf("Creating test pod")
	e.kubectl(
		"run", "--rm", "-it", "--restart=Never", "--labels=app=alpine",
		"--image=registry.fedoraproject.org/fedora-minimal:latest",
		"fedora", "--", "echo", "test",
	)

	resourceName := recordingName + "-fedora"
	profile := e.kubectl("get", "sp", resourceName, "-o", "yaml")
	defer e.kubectl("delete", "sp", resourceName)
	e.Contains(profile, "prctl")
	e.NotContains(profile, "mkdir")
}

func (e *e2e) testCaseProfileRecordingMultiContainer() {
	e.profileRecordingTestCase()

	e.logf("Creating recording for multi container test")
	e.kubectl("create", "-f", exampleRecordingPath)
	defer e.kubectl("delete", "-f", exampleRecordingPath)

	e.logf("Creating test pod")
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
	defer os.Remove(testPodFile.Name())
	_, err = testPodFile.Write([]byte(testPod))
	e.Nil(err)
	err = testPodFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", testPodFile.Name())

	e.logf("Waiting for test pod to be initialized")
	e.waitFor("condition=ready", "pod", "my-pod")
	e.kubectl("delete", "pod", "my-pod")

	profileRedis := e.kubectl("get", "sp", recordingName+"-redis", "-o", "yaml")
	profileNginx := e.kubectl("get", "sp", recordingName+"-nginx", "-o", "yaml")
	defer e.kubectl("delete", "sp", "--all")
	e.Contains(profileNginx, "unlink")
	e.Contains(profileRedis, "nanosleep")
}

func (e *e2e) testCaseProfileRecordingDeployment() {
	e.profileRecordingTestCase()

	e.logf("Creating recording for deployment test")
	e.kubectl("create", "-f", exampleRecordingPath)
	defer e.kubectl("delete", "-f", exampleRecordingPath)

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
	defer os.Remove(testFile.Name())
	_, err = testFile.Write([]byte(testDeployment))
	e.Nil(err)
	err = testFile.Close()
	e.Nil(err)
	e.kubectl("create", "-f", testFile.Name())

	e.logf("Waiting for pods to be initialized")
	e.waitFor("condition=available", "deployment", "my-deployment")
	e.kubectl("delete", "deploy", "my-deployment")

	e.retry(func(i int) bool {
		e.logf("Waiting for profiles to be available (%d)", i)
		output := e.kubectl("get", "sp")
		return strings.Contains(output, "nginx-0") && strings.Contains(output, "nginx-1")
	})
	e.logf("All profiles available")

	profile0 := e.kubectl("get", "sp", recordingName+"-nginx-0", "-o", "yaml")
	profile1 := e.kubectl("get", "sp", recordingName+"-nginx-1", "-o", "yaml")
	e.Contains(profile0, "unlink")
	e.Contains(profile1, "unlink")
	defer e.kubectl("delete", "sp", recordingName+"-nginx-0")
	defer e.kubectl("delete", "sp", recordingName+"-nginx-1")
}
