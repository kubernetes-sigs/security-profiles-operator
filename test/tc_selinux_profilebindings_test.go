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
	"strings"
)

const (
	selinuxTestProfileName = "testpolicy"
	selinuxBindingName     = "profile-binding-selinux"
	testPodName            = "selinux-profile-test-pod"
)

func (e *e2e) testCaseSelinuxProfileBinding() {
	e.selinuxOnlyTestCase()

	cleanup := e.profileBindingTestPrep(nsBindingEnabled, true, , "busybox:latest")
	defer cleanup()

	e.logf("the workload should not have errored")
	log := e.kubectl("logs", testPodName, "-c", "errorloggerbinding")
	e.Emptyf(log, "container should not have returned a 'Permissions Denied' error")

	namespace := e.getCurrentContextNamespace(defaultNamespace)

	e.logf("Getting selinux profile usage")
	selinuxUsage := e.getSELinuxPolicyUsage(selinuxTestProfileName)

	e.logf("Testing that pod has securityContext")
	output := e.kubectl(
		"get", "pod", testPodName,
		"--output", "jsonpath={.spec.initContainers[0].securityContext.seLinuxOptions.type}",
	)
	e.Equal(selinuxUsage, output)

	e.logf("Testing that profile binding has pod reference")
	output = e.kubectl("get", "profilebinding", selinuxBindingName, "--output", "jsonpath={.status.activeWorkloads[0]}")
	e.Equal(fmt.Sprintf("%s/%s", namespace, testPodName), output)
	output = e.kubectl("get", "profilebinding", selinuxBindingName, "--output", "jsonpath={.metadata.finalizers[0]}")
	e.Equal("active-workload-lock", output)

	e.logf("Testing that profile has pod reference")
	output = e.kubectl("get", "selinuxprofile", selinuxTestProfileName,
		"--output", "jsonpath={.status.activeWorkloads[0]}")

	e.Equal(fmt.Sprintf("%s/%s", namespace, testPodName), output)
	output = e.kubectl("get", "selinuxprofile", selinuxTestProfileName,
		"--output", "jsonpath={.metadata.finalizers[*]}")

	e.Contains(output, "in-use-by-active-pods")
}

func (e *e2e) testCaseSelinuxDefaultProfileBinding() {
	e.selinuxOnlyTestCase()

	cleanup := e.profileBindingTestPrep(nsBindingEnabled, true, , "busybox:latest")
	defer cleanup()

	e.logf("the workload should not have errored")
	log := e.kubectl("logs", testPodName, "-c", "errorloggerbinding")
	e.Emptyf(log, "container should not have returned a 'Permissions Denied' error")

	namespace := e.getCurrentContextNamespace(defaultNamespace)

	e.logf("Getting selinux profile usage")
	selinuxUsage := e.getSELinuxPolicyUsage(selinuxTestProfileName)

	e.logf("Testing that pod has securityContext")
	output := e.kubectl(
		"get", "pod", testPodName,
		"--output", "jsonpath={.spec.initContainers[0].securityContext.seLinuxOptions.type}",
	)
	e.Equal(selinuxUsage, output)

	e.logf("Testing that profile binding has pod reference")
	output = e.kubectl("get", "profilebinding", selinuxBindingName, "--output", "jsonpath={.status.activeWorkloads[0]}")
	e.Equal(fmt.Sprintf("%s/%s", namespace, testPodName), output)
	output = e.kubectl("get", "profilebinding", selinuxBindingName, "--output", "jsonpath={.metadata.finalizers[0]}")
	e.Equal("active-workload-lock", output)

	e.logf("Testing that profile has pod reference")
	output = e.kubectl("get", "selinuxprofile", selinuxTestProfileName,
		"--output", "jsonpath={.status.activeWorkloads[0]}")

	e.Equal(fmt.Sprintf("%s/%s", namespace, testPodName), output)
	output = e.kubectl("get", "selinuxprofile", selinuxTestProfileName,
		"--output", "jsonpath={.metadata.finalizers[*]}")

	e.Contains(output, "in-use-by-active-pods")
}

func (e *e2e) testCaseSelinuxProfileBindingNsNotEnabled() {
	e.selinuxOnlyTestCase()

	cleanup := e.profileBindingTestPrep(nsBindingDisabled, false, "busybox:latest")
	defer cleanup()

	e.logf("the workload should have errored")
	log := e.kubectl("logs", testPodName, "-c", "errorloggerbinding")
	e.NotEmptyf(log, "container should have returned a 'Permissions Denied' error")
}

func (e *e2e) profileBindingTestPrep(
	ns string,
	labelNs bool,
	image string,
) func() {
	selinuxTestProfile := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1alpha2
kind: SelinuxProfile
metadata:
  name: %s
spec:
  allow:
    var_log_t:
      dir:
        - open
        - read
        - getattr
        - lock
        - search
        - ioctl
        - add_name
        - remove_name
        - write
      file:
        - getattr
        - read
        - write
        - append
        - ioctl
        - lock
        - map
        - open
        - create
      sock_file:
        - getattr
        - read
        - write
        - append
        - open
`, selinuxTestProfileName)

	selinuxBinding := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileBinding
metadata:
  name: %s
spec:
  profileRef:
    kind: SelinuxProfile
    name: %s
  image: %s
`, selinuxBindingName, selinuxTestProfileName, image)

	testPod := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  initContainers:
  - image: %s
    name: errorloggerbinding
    command: ["sh"]
    args: ["-c", "echo \"Time: $(date). Some error info.\" >> /var/log/test.log || /bin/true"]
    volumeMounts:
    - name: varlog
      mountPath: /var/log
  containers:
  - name: pauser
    image: "gcr.io/google_containers/pause:latest"
  restartPolicy: Never
  volumes:
  - name: varlog
    hostPath:
      path: /var/log
      type: Directory
`, testPodName, image)

	restoreNs := e.switchToNs(ns)
	if labelNs {
		e.enableBindingHookInNs(ns)
	}

	e.logf("creating policy")
	e.writeAndCreate(selinuxTestProfile, "selinuxProfile-test.yml")

	// Let's wait for the policy to be processed
	e.kubectl("wait", "--timeout", defaultSelinuxOpTimeout,
		"--for", "condition=ready", "selinuxprofile", selinuxTestProfileName)

	e.logf("Creating test profile binding")
	e.writeAndCreate(selinuxBinding, "selinuxPolicyBinding-test.yml")

	e.logf("Creating test pod")
	e.writeAndCreate(testPod, "selinuxBindingPod-test.yml")

	output := e.kubectl("get", "pod", testPodName)
	for strings.Contains(output, "ContainerCreating") {
		output = e.kubectl("get", "pod", testPodName)
	}

	e.waitFor("condition=ready", "pod", testPodName)
	return func() {
		defer restoreNs()
		defer e.kubectl("delete", "selinuxprofile", selinuxTestProfileName)
		defer e.kubectl("delete", "profilebinding", selinuxBindingName)
		defer e.kubectl("delete", "pod", testPodName)
	}
}
