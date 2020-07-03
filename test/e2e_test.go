// +build e2e

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

func (e *e2e) TestSeccompOperator() {
	const manifest = "deploy/operator-non-root.yaml"

	// Ensure that we do not accidentally pull the image and use the pre-loaded
	// ones from the nodes
	e.run(
		"sed", "-i", "s;imagePullPolicy: Always;imagePullPolicy: Never;g",
		manifest,
	)
	defer e.run("git", "checkout", manifest)

	// Deploy the operator
	e.kubectl("create", "-f", manifest)

	// Wait for the operator to be ready
	e.kubectl(
		"-n", "seccomp-operator",
		"wait", "--for", "condition=ready", "pod", "--all",
	)
}
