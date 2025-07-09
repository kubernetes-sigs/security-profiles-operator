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

import "sigs.k8s.io/security-profiles-operator/internal/pkg/config"

func (e *e2e) TestSecurityProfilesOperator_Flaky() {
	if e.skipFlakyTests {
		e.T().Skip("Skipping flaky tests")

		return
	}

	// If we ran the non-flaky tests before, we would have ran them with the
	// context set to the test-ns namespace. Reset the context.
	e.kubectl("config", "set-context", "--current", "--namespace", config.OperatorName)

	e.waitForReadyPods()

	// Deploy prerequisites
	e.deployCertManager()

	// Deploy the operator
	e.deployOperator(e.operatorManifest)

	// Retrieve the inputs for the test cases
	nodes := e.getWorkerNodes()

	// Execute the test cases. Each test case should cleanup on its own and
	// leave a working operator behind.
	e.logf("testing cluster-wide operator")

	testCases := []testCase{
		{
			"Seccomp: Metrics",
			e.testCaseSeccompMetrics,
		},
		{
			"SPOD: Test webhook HTTP version",
			e.testCaseWebhookHTTP,
		},
		{
			"SPOD: Test Metrics HTTP version",
			e.testCaseMetricsHTTP,
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
		e.testCaseSeccompProfileBinding(nodes, "quay.io/security-profiles-operator/test-hello-world:latest")
		e.testCaseSeccompProfileBinding(nodes, "'*'")
	})

	e.Run("cluster-wide: Seccomp: Verify profile recording logs", func() {
		e.testCaseProfileRecordingStaticPodLogs()
		e.testCaseProfileRecordingMultiContainerLogs()
		e.testCaseProfileRecordingSpecificContainerLogs()
		e.testCaseProfileRecordingDeploymentLogs()
		e.testCaseRecordingFinalizers()
		e.testCaseProfileRecordingDeploymentScaleUpDownLogs()
		e.testCaseProfileRecordingWithMemoryOptimization()
	})

	e.Run("cluster-wide: Seccomp: Verify profile recording bpf", func() {
		e.testCaseBpfRecorderKubectlRun()
		e.testCaseBpfRecorderStaticPod()
		e.testCaseBpfRecorderMultiContainer()
		e.testCaseBpfRecorderDeployment()
		e.testCaseBpfRecorderParallel()
		e.testCaseBpfRecorderSelectContainer()
		e.testCaseBpfRecorderWithMemoryOptimization()
	})

	// Clean up cluster-wide deployment to prepare for namespace deployment
	e.cleanupOperator(e.operatorManifest)
	e.run("git", "checkout", e.operatorManifest)

	e.testNamespacedOperator(namespaceManifest, testNamespace, testCases, nodes)
}
