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
	"time"
)

const whNamespaceSelector = `{"matchExpressions":[{"key":"prod","operator":"In","values":["true"]}]}`

func (e *e2e) testCaseWebhookOptionsChange([]string) {
	if !e.testWebhookConfig {
		e.T().Skip("Skipping webhook config related tests")
	}
	e.logf("Change webhook options")
	origOutput0 := e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].namespaceSelector}")
	origOutput1 := e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].namespaceSelector}")

	whPatch := fmt.Sprintf(`{"spec":{"webhookOptions":[{"name":"binding.spo.io","failurePolicy":"Ignore","namespaceSelector":%s}]}}`, whNamespaceSelector) //nolint:lll // very long patch line
	e.logf(whPatch)
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", whPatch, "--type=merge")
	time.Sleep(defaultWaitTime)

	// check the configured hook
	output := e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[0].failurePolicy}")
	e.Equal("Ignore", output)
	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[0].namespaceSelector}")
	e.Equal(whNamespaceSelector, output)

	// check the other hook did not change
	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].failurePolicy}")
	e.Equal("Fail", output)
	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].namespaceSelector}")
	e.Equal(origOutput1, output)

	// go back to defaults
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"webhookOptions":[]}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	// check we are back to defaults
	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[0].failurePolicy}")
	e.Equal("Fail", output)

	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[0].namespaceSelector}")
	e.Equal(origOutput0, output)

	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].failurePolicy}")
	e.Equal("Fail", output)

	output = e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath={.webhooks[1].namespaceSelector}")
	e.Equal(origOutput1, output)
}
