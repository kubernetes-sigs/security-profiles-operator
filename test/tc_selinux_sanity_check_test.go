/*
Copyright 2020 The Kubernetes Authors.

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

func (e *e2e) testCaseSelinuxSanityCheck([]string) {
	e.selinuxtOnlyTestCase()

	const podWithoutPolicy = `
apiVersion: v1
kind: Pod
metadata:
  name: el-no-policy
spec:
  initContainers:
  - name: errorlogger
    image: "registry.access.redhat.com/ubi8/ubi-minimal:latest"
    command: ["/bin/bash"]
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
`
	e.logf("sanity check: The 'errorlogger' workload should be blocked by SELinux")

	e.logf("creating workload")
	e.writeAndCreate(podWithoutPolicy, "pod-wo-policy.yml")

	e.kubectl("wait", "--for", "condition=ready", "pod", "el-no-policy")

	e.logf("the workload should have errored")
	expectedLog := "/bin/bash: /var/log/test.log: Permission denied"
	log := e.kubectl("logs", "el-no-policy", "-c", "errorlogger")
	e.Equalf(log, expectedLog, "container should have returned a 'Permissions Denied' error")

	e.kubectl("delete", "pod", "el-no-policy")
}
