/*
Copyright 2023 The Kubernetes Authors.

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
	"time"
)

const (
	defaultAppArmorOpTimeout = "60s"
	errorloggerProfile       = `
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: AppArmorProfile
metadata:
  name: aa-errorlogger-profile
spec:
  policy: |
    #include <tunables/global>

    profile aa-errorlogger-profile flags=(attach_disconnected) {
      #include <abstractions/base>

      file,

      # Deny all file writes.
      deny /** w,
    }
`

	//nolint:lll // full yaml
	aaPodWithPolicyFmt = `
apiVersion: v1
kind: Pod
metadata:
  name: aa-errorlogger
  annotations:
    container.apparmor.security.beta.kubernetes.io/errorlogger: localhost/%s
spec:
  containers:
  - name: errorlogger
    image: "registry.access.redhat.com/ubi8/ubi-minimal:latest"
    command: ["/bin/bash"]
    args: [ "-c","set -eux; echo 'Hello AppArmor!' && sleep 1h" ]
  restartPolicy: Never
`
)

func (e *e2e) testCaseAppArmorBaseUsage(nodes []string) {
	e.apparmorOnlyTestCase()

	e.logf("The 'errorlogger' workload should be able to use AppArmor profile")

	e.logf("creating profile")
	e.writeAndCreate(errorloggerProfile, "errorlogger-profile.yml")

	profileName := "aa-errorlogger-profile"

	e.logf("assert profile is installed")
	e.assertAppArmorProfileIsInstalled(nodes, profileName, maxNodeIterations, sleepBetweenIterations)

	e.logf("creating workload")

	podWithPolicy := fmt.Sprintf(aaPodWithPolicyFmt, profileName)
	e.writeAndCreate(podWithPolicy, "pod-w-profile.yml")

	podName := "aa-errorlogger"

	e.waitFor("condition=ready", "pod", podName)

	e.logf("the workload should be running")
	podWithPolicyPhase := e.kubectl(
		"get", "pods", podName, "-o", "jsonpath={.status.phase}")
	e.Truef(strings.EqualFold(podWithPolicyPhase, "running"),
		"The pod without profile's phase should be 'Running', instead it's: %s",
		podWithPolicyPhase)

	e.logf("cleaning up")

	e.logf("removing workload")
	e.kubectl("delete", "pod", podName)

	e.logf("removing profile")
	e.kubectl("delete", "apparmorprofile", profileName)

	e.logf("assert profile was removed")
	e.assertAppArmorProfileIsRemoved(nodes, profileName, maxNodeIterations, sleepBetweenIterations)
}

func (e *e2e) assertAppArmorProfileIsInstalled(
	nodes []string, profile string, nodeIterations int, sleep time.Duration,
) {
	for i := 0; i < nodeIterations; i++ {
		var missingPolName string

		for _, node := range nodes {
			allLoaddedProfiles := e.execNode(node, "sudo", "aa-status")
			loadedProifles := []string{}
			for _, p := range strings.Split(allLoaddedProfiles, "\n") {
				p = strings.TrimSpace(p)
				loadedProifles = append(loadedProifles, p)
			}
			if !e.sliceContainsString(loadedProifles, profile) {
				missingPolName = node
				break
			}
		}

		if missingPolName != "" {
			if i == nodeIterations-1 {
				e.Fail(fmt.Sprintf(
					"The AppArmorProfile %s wasn't found in the %s node",
					profile, missingPolName,
				))
			} else {
				e.logf(fmt.Sprintf("The profile %s wasn't found, trying again", profile))
				time.Sleep(sleep)
			}
		}
	}
}

func (e *e2e) assertAppArmorProfileIsRemoved(nodes []string, profile string, nodeIterations int, sleep time.Duration) {
	for i := 0; i < nodeIterations; i++ {
		var missingPolName string

		for _, node := range nodes {
			loadedProfiles := e.execNode(node, "sudo", "cat", "/sys/kernel/security/apparmor/profiles")
			if e.sliceContainsString(strings.Split(loadedProfiles, "\n"), profile) {
				missingPolName = node
				break
			}
		}

		if missingPolName != "" {
			if i == nodeIterations-1 {
				e.Fail(fmt.Sprintf(
					"The AppArmor errorlogger was found in the %s node with the name %s",
					missingPolName, profile,
				))
			} else {
				e.logf("the profile was stil present, trying again")
				time.Sleep(sleep)
			}
		}
	}
}
