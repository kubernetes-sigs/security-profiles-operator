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
	"time"
)

func (e *e2e) testCaseMemOptmEnable([]string) {
	e.logf("Change memory optimization in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableMemoryOptimization": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	e.waitForSpod()
	e.waitInOperatorNSFor("condition=initialized", "pod", "-l", "name=spod")
	e.waitInOperatorNSFor("condition=ready", "pod", "-l", "name=spod")
}
