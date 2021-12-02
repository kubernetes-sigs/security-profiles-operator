//go:build flake
// +build flake

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

func (e *e2e) runClusterWideTests(nodes []string) {
	// Execute the test cases. Each test case should cleanup on its own and
	// leave a working operator behind.
	e.logf("testing cluster-wide operator")
	testCases := []struct {
		description string
		fn          func(nodes []string)
	}{
		{
			"Seccomp: Metrics",
			e.testCaseSeccompMetrics,
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

	e.Run("cluster-wide: Seccomp: Verify profile recording bpf", func() {
		e.enableBpfRecorderInSpod()
		e.testCaseBpfRecorderKubectlRun()
		e.testCaseBpfRecorderStaticPod()
		e.testCaseBpfRecorderMultiContainer()
		e.testCaseBpfRecorderDeployment()
		e.testCaseBpfRecorderParallel()
	})
}

func (e *e2e) runNamespacedTests(nodes []string) {
	testCases := []struct {
		description string
		fn          func(nodes []string)
	}{
		{
			"SELinux: Metrics (update, delete)",
			e.testCaseSelinuxMetrics,
		},
	}

	for _, testCase := range testCases {
		tc := testCase
		e.Run("namespaced: "+tc.description, func() {
			tc.fn(nodes)
		})
	}
}
