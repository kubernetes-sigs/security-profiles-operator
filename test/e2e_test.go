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

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/release-utils/command"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	certmanager       = "https://github.com/jetstack/cert-manager/releases/download/v1.7.1/cert-manager.yaml"
	manifest          = "deploy/operator.yaml"
	namespaceManifest = "deploy/namespace-operator.yaml"
	testNamespace     = "test-ns"
	defaultNamespace  = "default"
	// NOTE(jaosorior): We should be able to decrease this once we
	// migrate to a single daemonset-based implementation for the
	// SELinux pieces.
	defaultSelinuxOpTimeout     = "360s"
	defaultLogEnricherOpTimeout = defaultSelinuxOpTimeout
	defaultBpfRecorderOpTimeout = defaultSelinuxOpTimeout
	defaultWaitTimeout          = "180s"
	defaultWaitTime             = 15 * time.Second
)

func (e *e2e) TestSecurityProfilesOperator() {
	e.waitForReadyPods()

	// Deploy prerequisites
	e.deployCertManager()

	// Deploy the operator
	e.deployOperator(manifest)

	// Retrieve the inputs for the test cases
	nodes := e.getWorkerNodes()

	// Execute the test cases. Each test case should cleanup on its own and
	// leave a working operator behind.
	e.logf("testing cluster-wide operator")
	testCases := []struct {
		description string
		fn          func(nodes []string)
	}{
		{
			"Seccomp: Verify default and example profiles",
			e.testCaseDefaultAndExampleProfiles,
		},
		{
			"Seccomp: Run a test pod",
			e.testCaseRunPod,
		},
		{
			"Seccomp: Verify base profile merge",
			e.testCaseBaseProfile,
		},
		{
			"Seccomp: Delete profiles",
			e.testCaseDeleteProfiles,
		},
		{
			"Seccomp: Metrics",
			e.testCaseSeccompMetrics,
		},
		{
			"Seccomp: Re-deploy the operator",
			e.testCaseReDeployOperator,
		},
		{
			"Log Enricher",
			e.testCaseLogEnricher,
		},
		{
			"SELinux: sanity check",
			e.testCaseSelinuxSanityCheck,
		},
		{
			"SELinux: base case (install policy, run pod and delete)",
			e.testCaseSelinuxBaseUsage,
		},
		{
			"SELinux: Metrics (update, delete)",
			e.testCaseSelinuxMetrics,
		},
		{
			"SPOD: Update SELinux flag",
			e.testCaseSPODUpdateSelinux,
		},
		{
			"SPOD: Change verbosity",
			e.testCaseVerbosityChange,
		},
		{
			"Seccomp: make sure statuses for profiles with long names can be listed",
			e.testCaseLongSeccompProfileName,
		},
	}
	for _, testCase := range testCases {
		tc := testCase
		e.Run("cluster-wide: "+tc.description, func() {
			tc.fn(nodes)
		})
	}

	// TODO(jaosorior): Re-introduce this to the namespaced tests once we
	// fix the issue with the certs.
	e.Run("cluster-wide: Seccomp: Verify profile binding", func() {
		e.testCaseProfileBinding(nodes)
	})

	e.Run("cluster-wide: Seccomp: Verify profile recording hook", func() {
		e.testCaseProfileRecordingStaticPodHook()
		e.testCaseProfileRecordingKubectlRunHook()
		e.testCaseProfileRecordingMultiContainerHook()
		e.testCaseProfileRecordingDeploymentHook()
	})

	e.Run("cluster-wide: Seccomp: Verify profile recording logs", func() {
		e.testCaseProfileRecordingStaticPodLogs()
		e.testCaseProfileRecordingMultiContainerLogs()
		e.testCaseProfileRecordingSpecificContainerLogs()
		e.testCaseProfileRecordingDeploymentLogs()
	})

	e.Run("cluster-wide: Selinux: Verify SELinux profile recording logs", func() {
		e.testCaseProfileRecordingStaticPodSELinuxLogs()
		e.testCaseProfileRecordingMultiContainerSELinuxLogs()
		e.testCaseProfileRecordingSelinuxDeploymentLogs()
	})

	e.Run("cluster-wide: Seccomp: Verify profile recording bpf", func() {
		e.testCaseBpfRecorderKubectlRun()
		e.testCaseBpfRecorderStaticPod()
		e.testCaseBpfRecorderMultiContainer()
		e.testCaseBpfRecorderDeployment()
		e.testCaseBpfRecorderParallel()
		e.testCaseBpfRecorderSelectContainer()
	})

	// Clean up cluster-wide deployment to prepare for namespace deployment
	e.cleanupOperator(manifest)
	e.run("git", "checkout", manifest)

	e.logf("testing namespace operator")

	// Use namespace manifests for redeploy test
	testCases[5].fn = e.testCaseReDeployNamespaceOperator

	// Deploy the namespace operator
	e.kubectl("create", "namespace", testNamespace)
	e.run(
		"sed", "-i", fmt.Sprintf("s/NS_REPLACE/%s/", testNamespace),
		namespaceManifest,
	)
	// All following operations such as create pod will be in the test namespace
	e.kubectl("config", "set-context", "--current", "--namespace", testNamespace)
	e.deployOperator(namespaceManifest)

	for _, testCase := range testCases {
		tc := testCase
		e.Run("namespaced: "+tc.description, func() {
			tc.fn(nodes)
		})
	}
	e.run("git", "checkout", namespaceManifest)
}

func (e *e2e) deployCertManager() {
	e.logf("Deploying cert-manager")
	e.kubectl("apply", "-f", certmanager)

	// https://cert-manager.io/docs/installation/kubernetes/#verifying-the-installation
	e.waitFor(
		"condition=ready",
		"--namespace", "cert-manager",
		"pod", "-l", "app.kubernetes.io/instance=cert-manager",
	)

	tries := 20
	certManifest := `
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-test
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: test-selfsigned
  namespace: cert-manager-test
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: selfsigned-cert
  namespace: cert-manager-test
spec:
  dnsNames:
    - example.com
  secretName: selfsigned-cert-tls
  issuerRef:
    name: test-selfsigned
`

	file, err := ioutil.TempFile(os.TempDir(), "test-resource*.yaml")
	e.Nil(err)
	_, err = file.Write([]byte(certManifest))
	e.Nil(err)
	defer os.Remove(file.Name())
	for i := 0; i < tries; i++ {
		output, err := command.New(e.kubectlPath, "apply", "-f", file.Name()).Run()
		e.Nil(err)
		if output.Success() {
			break
		}
		time.Sleep(defaultWaitTime)
	}
	e.waitFor(
		"condition=Ready",
		"certificate", "selfsigned-cert",
		"--namespace", "cert-manager-test",
	)
}

func (e *e2e) deployOperator(manifest string) {
	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.logf("Setting imagePullPolicy to '%s' in manifest: %s", e.pullPolicy, manifest)
	e.run(
		"sed", "-i",
		fmt.Sprintf("s;imagePullPolicy: Always;imagePullPolicy: %s;g", e.pullPolicy),
		manifest,
	)

	// Update the image name to match the test image
	e.run(
		"sed", "-i", fmt.Sprintf("s;image: .*gcr.io/.*;image: %s;g", e.testImage),
		manifest,
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s;value: .*gcr.io/.*;value: %s;g", e.testImage),
		manifest,
	)
	e.run(
		"sed", "-i", fmt.Sprintf("s;value: .*quay.io/.*/selinuxd.*;value: %s;g", e.selinuxdImage),
		manifest,
	)

	if e.selinuxEnabled {
		e.run(
			"sed", "-i", "s/enableSelinux: false/enableSelinux: true/",
			manifest,
		)
	}

	// Deploy the operator
	e.logf("Deploying operator")
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.logf("Waiting for operator to be ready")
	// Wait for deployment
	e.waitInOperatorNSFor("condition=available", "deployment", "-l", "app=security-profiles-operator")
	// Wait for all pods in deployment
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "app=security-profiles-operator")
	// Wait for all pods in DaemonSet
	e.waitForSpod()
	e.waitInOperatorNSFor("condition=initialized", "pod", "-l", "name=spod")
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
	// Wait for spod to be available
	for {
		if res, err := command.New(
			e.kubectlPath, "-n", config.OperatorName, "get", "spod", "spod",
		).Run(); err == nil && res.Success() {
			break
		}
		time.Sleep(time.Second)
	}
}

func (e *e2e) cleanupOperator(manifest string) {
	// Clean up the operator
	e.logf("Cleaning up operator")
	e.kubectl("delete", "seccompprofiles", "--all", "--all-namespaces")
	e.kubectl("delete", "--ignore-not-found", "-f", manifest)
}

func (e *e2e) getWorkerNodes() []string {
	e.logf("Getting worker nodes")
	nodesOutput := e.kubectl(
		"get", "nodes",
		"-l", "node-role.kubernetes.io/master!=",
		"-o", `jsonpath={range .items[*]}{@.metadata.name}{" "}{end}`,
	)
	nodes := strings.Fields(nodesOutput)
	e.logf("Got worker nodes: %v", nodes)

	return nodes
}

func (e *e2e) getSeccompProfile(name, namespace string) *seccompprofileapi.SeccompProfile {
	seccompProfileJSON := e.kubectl(
		"-n", namespace, "get", "seccompprofile", name, "-o", "json",
	)
	seccompProfile := &seccompprofileapi.SeccompProfile{}
	e.Nil(json.Unmarshal([]byte(seccompProfileJSON), seccompProfile))
	return seccompProfile
}

func (e *e2e) getSeccompProfileNodeStatus(
	id, namespace, node string,
) *secprofnodestatusv1alpha1.SecurityProfileNodeStatus {
	selector := fmt.Sprintf("spo.x-k8s.io/node-name=%s,spo.x-k8s.io/profile-id=SeccompProfile-%s", node, id)
	seccompProfileNodeStatusJSON := e.kubectl(
		"-n", namespace, "get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
	e.Nil(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))
	e.Equal(len(secpolNodeStatusList.Items), 1)
	return &secpolNodeStatusList.Items[0]
}

func (e *e2e) getAllSeccompProfileNodeStatuses(
	id, namespace string,
) *secprofnodestatusv1alpha1.SecurityProfileNodeStatusList {
	selector := fmt.Sprintf("spo.x-k8s.io/profile-id=SeccompProfile-%s", id)
	seccompProfileNodeStatusJSON := e.kubectl(
		"-n", namespace, "get", "securityprofilenodestatus", "-l", selector, "-o", "json",
	)
	secpolNodeStatusList := &secprofnodestatusv1alpha1.SecurityProfileNodeStatusList{}
	e.Nil(json.Unmarshal([]byte(seccompProfileNodeStatusJSON), secpolNodeStatusList))
	return secpolNodeStatusList
}

func (e *e2e) getCurrentContextNamespace(alt string) string {
	ctxns := e.kubectl("config", "view", "--minify", "-o", "jsonpath={..namespace}")
	if ctxns == "" {
		ctxns = alt
	}
	return ctxns
}

func (e *e2e) writeAndCreate(manifest, filePattern string) func() {
	file, err := ioutil.TempFile(os.TempDir(), filePattern)
	fileName := file.Name()
	e.Nil(err)
	_, err = file.Write([]byte(manifest))
	e.Nil(err)
	err = file.Close()
	e.Nil(err)
	e.kubectl("create", "-f", fileName)
	return func() { os.Remove(fileName) }
}

func (e *e2e) getSELinuxPolicyName(policy string) string {
	usageStr := e.getSELinuxPolicyUsage(policy)
	// Udica (the library that helps out generate SELinux policies),
	// adds .process in the end of the usage. So we need to remove it
	// to get the module name
	return strings.TrimSuffix(usageStr, ".process")
}

func (e *e2e) getSELinuxPolicyUsage(policy string) string {
	ns := e.getCurrentContextNamespace(defaultNamespace)
	// This describes the usage string, which is not necessarily
	// the name of the policy in the node
	return e.kubectl("get", "selinuxprofile", "-n", ns, policy, "-o", "jsonpath={.status.usage}")
}

func (e *e2e) sliceContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func (e *e2e) waitForSpod() {
	for i := 0; i < 50; i++ {
		output, err := command.New(
			e.kubectlPath, "-n", config.OperatorName,
			"get", "pod", "-l", "name=spod",
		).RunSilent()
		e.Nil(err)
		if !strings.Contains(output.Error(), "No resources found") {
			return
		}
		e.logf("Waiting for resource to be available (%d)", i)
		time.Sleep(3 * time.Second)
	}

	e.Fail("Timed out to wait for resource")
}

func (e *e2e) retryGet(args ...string) string {
	for i := 0; i < 20; i++ {
		output, err := command.New(
			e.kubectlPath, append([]string{"get"}, args...)...,
		).RunSilent()
		e.Nil(err)
		if !strings.Contains(output.Error(), "not found") {
			return output.OutputTrimNL()
		}
		e.logf("Waiting for resource to be available (%d)", i)
		time.Sleep(3 * time.Second)
	}

	e.Fail("Timed out to wait for resource")
	return ""
}

func (e *e2e) exists(args ...string) bool {
	output, err := command.New(
		e.kubectlPath, append([]string{"get"}, args...)...,
	).RunSilent()
	e.Nil(err)
	return !strings.Contains(output.Error(), "not found")
}

func (e *e2e) getSeccompPolicyID(profile string) string {
	ns := e.getCurrentContextNamespace(defaultNamespace)
	return e.kubectl("get", "sp", "-n", ns, profile, "-o", "jsonpath={.metadata.labels.spo\\.x-k8s\\.io/profile-id}")
}
