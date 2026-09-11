/*
Copyright The Kubernetes Authors.

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
	"path"
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// The recorded base profiles live under this prefix, one artifact per runtime
// with the recorded runtime version as the tag. On main this is the staging
// registry, which the staging build refreshes on every merge, so a new
// recording is available to the next test run without a promotion. The
// release script points it at registry.k8s.io, so a release branch exercises
// the promoted artifact, and the back-to-dev script switches it back.
const baseProfileRegistry = "oci://gcr.io/k8s-staging-sp-operator/base/"

// baseProfileArtifact returns the artifact reference of the recorded base
// profile for the runtime. The tag is the version from the recorded profile's
// metadata.name, so re-recording against a new runtime version needs no edit
// here.
func (e *e2e) baseProfileArtifact(runtime string) string {
	name := e.recordedBaseProfileName(fmt.Sprintf("examples/baseprofile-%s.yaml", runtime))

	version := strings.TrimPrefix(name, runtime+"-")
	e.Require().NotEqual(name, version,
		"recorded profile %q should be named <runtime>-<version>", name)

	return baseProfileRegistry + runtime + ":" + version
}

// testCaseBaseProfileOCIRuntimeFormat verifies that a base profile referencing
// an artifact in the runtime format, a single raw runtime-spec JSON layer with
// the seccomp config media type, is pulled, merged and applied. The artifact
// side of that format is covered by unit tests; this exercises the operator
// pulling one it did not create itself.
func (e *e2e) testCaseBaseProfileOCIRuntimeFormat(nodes []string) {
	e.seccompOnlyTestCase()

	// The published artifacts are unsigned, because the build that pushes them
	// has no OIDC identity for keyless signing.
	e.kubectlOperatorNS(
		"patch", "spod", "spod",
		"-p", `{"spec":{"security":{"disableOciArtifactSignatureVerification": true}}}`,
		"--type=merge",
	)
	time.Sleep(defaultWaitTime)
	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultLongOpTimeout)

	defer func() {
		e.kubectlOperatorNS(
			"patch", "spod", "spod",
			"-p", `{"spec":{"security":{"disableOciArtifactSignatureVerification": false}}}`,
			"--type=merge",
		)
		time.Sleep(defaultWaitTime)
		e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	}()

	runtime := "runc"
	if clusterType == clusterTypeVanilla && e.containerRuntime != containerRuntimeDocker {
		runtime = "crun"
	}

	baseProfileName := e.baseProfileArtifact(runtime)

	profileName := fmt.Sprintf("hello-oci-runtime-%v", time.Now().Unix())
	profileYAML := fmt.Sprintf(`
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: %s
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: %s
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - arch_prctl
    - set_tid_address
    - exit_group
`, profileName, baseProfileName)

	namespace := e.getCurrentContextNamespace(defaultNamespace)
	podName := fmt.Sprintf("pod-%v", time.Now().Unix())

	e.logf("Creating profile with a runtime format base profile")

	profileFile, err := os.CreateTemp("", "profile-*.yaml")
	e.Require().NoError(err)

	defer os.Remove(profileFile.Name())

	_, err = profileFile.WriteString(profileYAML)
	e.Require().NoError(err)
	e.Require().NoError(profileFile.Close())
	e.kubectl("create", "-f", profileFile.Name())

	defer e.kubectl("delete", "-f", profileFile.Name())

	e.logf("Waiting for profile to be reconciled")
	e.waitForProfile(profileName)

	// The merged profile only exists on the node, the custom resource keeps
	// the spec as written.
	localhostProfile := e.kubectl(
		"get", "sp", profileName, "-o", "jsonpath={.status.localhostProfile}",
	)
	e.Require().NotEmpty(localhostProfile)

	e.logf("Verifying that the base profile got merged into %s", localhostProfile)

	profilePath := path.Join(
		e.nodeRootfsPrefix, config.KubeletSeccompRootPath(), localhostProfile,
	)
	merged := e.execNode(nodes[0], "cat", profilePath)
	e.Contains(merged, "execve", "base profile syscalls are missing from the merged profile")
	e.Contains(merged, "arch_prctl", "profile syscalls are missing from the merged profile")

	podYAML := fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  containers:
  - image: quay.io/security-profiles-operator/test-hello-world:latest
    name: ctr
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: %s
  restartPolicy: OnFailure
`, podName, namespace, localhostProfile)

	e.logf("Creating pod")

	podFile, err := os.CreateTemp("", "pod-*.yaml")
	e.Require().NoError(err)

	defer os.Remove(podFile.Name())

	_, err = podFile.WriteString(podYAML)
	e.Require().NoError(err)
	e.Require().NoError(podFile.Close())
	e.kubectl("create", "-f", podFile.Name())

	defer e.kubectl("delete", "pod", podName)

	e.logf("Waiting for test pod to be initialized")
	e.waitFor("condition=initialized", "pod", podName)

	e.logf("Waiting for pod to be completed")

	completed := false

	for range 20 {
		output := e.kubectl("get", "pod", podName)
		if strings.Contains(output, "Completed") {
			completed = true

			break
		}

		if strings.Contains(output, "CreateContainerError") {
			e.kubectlOperatorNS("logs", "-l", "name=spod")
			e.FailNowf(
				"Unable to create container",
				"%s", e.kubectl("describe", "pod", podName),
			)
		}

		time.Sleep(time.Second)
	}

	if !completed {
		e.FailNowf(
			"Pod did not complete in time",
			"%s", e.kubectl("describe", "pod", podName),
		)
	}

	e.logf("Testing that container ran successfully")
	e.Contains(e.kubectl("logs", podName), "Hello from Docker!")
}
