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

func (e *e2e) testCaseReDeployOperator([]string) {
	e.seccompOnlyTestCase()

	// Clean up the operator
	e.cleanupOperator(e.operatorManifest)

	// Deploy the operator again
	e.deployOperator(e.operatorManifest)
}

func (e *e2e) testCaseReDeployNamespaceOperator([]string) {
	e.seccompOnlyTestCase()

	// Clean up the operator
	e.cleanupOperator(namespaceManifest)

	// Deploy the operator again
	e.deployOperator(namespaceManifest)
}
