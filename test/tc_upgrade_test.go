//go:build e2e

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
	"path/filepath"
	"strings"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// fallbackPreviousRelease is the release the upgrade starts from when
	// git cannot tell the latest one, for example in a clone without tags.
	fallbackPreviousRelease = "v1.1.0"
	releasedManifestURL     = "https://raw.githubusercontent.com/kubernetes-sigs/" +
		"security-profiles-operator/%s/deploy/operator.yaml"
	upgradeProfileName = "upgrade-profile"
	upgradeProfile     = `
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: ` + upgradeProfileName + `
spec:
  defaultAction: SCMP_ACT_LOG
`
)

// previousRelease returns the latest release tag before the tested commit.
func (e *e2e) previousRelease() string {
	tag, err := e.runCommand(
		"git", "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*",
	)
	if err != nil || tag == "" {
		e.logf("No previous release from git, using %s: %v", fallbackPreviousRelease, err)

		return fallbackPreviousRelease
	}

	return tag
}

// testCaseUpgradeFromPreviousRelease replaces the operator under test with
// the previous release, creates a profile, upgrades to the operator under
// test and checks that the profile stays installed.
func (e *e2e) testCaseUpgradeFromPreviousRelease([]string) {
	e.seccompOnlyTestCase()

	if strings.EqualFold(clusterType, clusterTypeOpenShift) {
		e.T().Skip("The released manifest does not target OpenShift")
	}

	release := e.previousRelease()
	e.logf("Upgrading from release %s", release)

	releasedManifest := filepath.Join(e.T().TempDir(), "operator-"+release+".yaml")
	e.run(
		"curl", "-fsSL", "--retry", "5", "-o", releasedManifest,
		fmt.Sprintf(releasedManifestURL, release),
	)

	defer e.switchToNs(defaultNamespace)()

	// Other test cases need the operator under test, so it gets deployed
	// again if the upgrade did not work out.
	upgraded := false

	defer func() {
		if upgraded {
			return
		}

		e.logf("Restoring the operator under test")
		e.cleanupOperator(e.operatorManifest)
		e.deployOperator(e.operatorManifest)
	}()

	e.cleanupOperator(e.operatorManifest)

	e.logf("Deploying the operator of release %s", release)
	e.createOperator(releasedManifest)
	e.waitForOperator()

	e.logf("Creating a profile with the operator of release %s", release)
	e.writeAndCreate(upgradeProfile, "upgrade-profile*.yaml")
	e.kubectlCleanup("sp", upgradeProfileName)
	e.waitForProfile(upgradeProfileName)

	generation := e.spodDaemonSetGeneration()

	e.logf("Upgrading to the operator under test")
	e.kubectl(
		"apply", "--server-side", "--force-conflicts",
		"-f", e.prepareManifest(e.operatorManifest),
	)
	e.kubectlOperatorNS(
		"rollout", "status", "deployment", config.OperatorName, "--timeout", defaultLongOpTimeout,
	)
	e.waitForSpodRollout(generation)

	image := e.kubectlOperatorNS(
		"get", "ds", "spod", "-o", "jsonpath={.spec.template.spec.containers[0].image}",
	)
	e.Require().Equal(e.testImage, image, "the spod does not run the image under test")

	e.logf("Checking that the profile is still installed")
	e.waitForProfile(upgradeProfileName)

	upgraded = true
}
