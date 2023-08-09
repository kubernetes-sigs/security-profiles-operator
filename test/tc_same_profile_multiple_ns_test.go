/*
Copyright 2022 The Kubernetes Authors.

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

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	dupNsName          = "dup-profile-ns"
	currentNsManifest  = "dup-policy-current.yml"
	newNsManifest      = "dup-policy-new.yml"
	dupProfileName     = "duplicate-profile"
	dupProfileTemplate = `
    apiVersion: security-profiles-operator.x-k8s.io/v1beta1
    kind: SeccompProfile
    metadata:
      name: %s
      namespace: %s
    spec:
      defaultAction: "SCMP_ACT_ALLOW"
`
)

func (e *e2e) testCaseSameProfileMultipleNs() {
	e.seccompOnlyTestCase()
	e.logf("Create the same profile in two namespaces")

	e.logf("creating policy in the current namespace")
	manifest := fmt.Sprintf(dupProfileTemplate, dupProfileName, config.OperatorName)
	deleteCurNsFn := e.writeAndCreate(manifest, currentNsManifest)
	defer deleteCurNsFn()

	e.logf("Waiting for profile in the operator NS to be reconciled")
	e.waitForProfile(dupProfileName, "-n", config.OperatorName)

	e.logf("Create a new NS")
	e.kubectl("create", "ns", dupNsName)
	manifest = fmt.Sprintf(dupProfileTemplate, dupProfileName, dupNsName)
	deleteNewNsFn := e.writeAndCreate(manifest, newNsManifest)
	defer deleteNewNsFn()

	e.logf("Waiting for profile in the new NS to be reconciled")
	e.kubectl("-n", dupNsName, "wait", "--timeout", defaultWaitTimeout, "--for", "condition=ready", "sp", dupProfileName)
}
