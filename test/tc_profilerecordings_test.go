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
)

const (
	exampleRecordingPath = "examples/profilerecording.yaml"
	recordingName        = "test-recording"
)

func (e *e2e) testCaseProfileRecordingStaticPod() {
	e.profileRecordingTestCase()

	e.logf("Creating recording")
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
    name: recording
    resources: {}
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

	profile := e.kubectl("get", "sp", recordingName, "-o", "yaml")
	defer e.kubectl("delete", "sp", recordingName)
	e.Contains(profile, "mkdir")
}

func (e *e2e) testCaseProfileRecordingKubectlRun() {
	e.profileRecordingTestCase()

	e.logf("Creating recording")
	e.kubectl("create", "-f", exampleRecordingPath)
	defer e.kubectl("delete", "-f", exampleRecordingPath)

	e.logf("Creating test pod")
	e.kubectl(
		"run", "--rm", "-it", "--restart=Never", "--labels=app=alpine",
		"--image=registry.fedoraproject.org/fedora-minimal:latest",
		"test", "--", "echo", "test",
	)

	profile := e.kubectl("get", "sp", recordingName, "-o", "yaml")
	e.Contains(profile, "prctl")
	e.NotContains(profile, "mkdir")
}
