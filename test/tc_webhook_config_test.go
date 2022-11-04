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

const (
	whNamespaceSelector = `{"matchExpressions":[{"key":"prod","operator":"In","values":["true"]}]}`
	whObjectSelector    = `{"matchExpressions":[{"key":"record-pod","operator":"In","values":["true"]}]}`
)

type whConfigOutput struct {
	name              string
	namespaceSelector string
	objectSelector    string
	failurePolicy     string
}

const (
	bindingIdx = iota
	recordingIdx
	numWebhooks
)

func (e *e2e) testCaseWebhookOptionsChange([]string) {
	if !e.testWebhookConfig {
		e.T().Skip("Skipping webhook config related tests")
	}
	e.logf("Change webhook options")

	whDefault := e.getAllWebhookAttributes()

	whPatch := fmt.Sprintf(`{"spec":{"webhookOptions":[{"name":"binding.spo.io","failurePolicy":"Ignore","namespaceSelector":%s, "objectSelector":%s}]}}`, whNamespaceSelector, whObjectSelector) //nolint:lll // very long patch line
	e.logf(whPatch)
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", whPatch, "--type=merge")
	time.Sleep(defaultWaitTime)

	// check the configured hook
	whPatchedConfig := e.getAllWebhookAttributes()
	e.Equal("Ignore", whPatchedConfig[bindingIdx].failurePolicy)
	e.Equal(whNamespaceSelector, whPatchedConfig[bindingIdx].namespaceSelector)
	e.Equal(whObjectSelector, whPatchedConfig[bindingIdx].objectSelector)
	// check the other hook did not change
	e.Equal("Fail", whPatchedConfig[recordingIdx].failurePolicy)
	e.Equal(whDefault[recordingIdx].namespaceSelector, whPatchedConfig[recordingIdx].namespaceSelector)

	// go back to defaults
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"webhookOptions":[]}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	// check we are back to defaults
	whRevertedConfig := e.getAllWebhookAttributes()
	e.Equal("Fail", whRevertedConfig[bindingIdx].failurePolicy)
	e.Equal(whDefault[bindingIdx].namespaceSelector, whRevertedConfig[bindingIdx].namespaceSelector)
	// check the other hook did not change
	e.Equal("Fail", whRevertedConfig[recordingIdx].failurePolicy)
	e.Equal(whDefault[recordingIdx].namespaceSelector, whRevertedConfig[recordingIdx].namespaceSelector)
}

func getWhConfigs() []*whConfigOutput {
	whConfigs := make([]*whConfigOutput, numWebhooks)
	whConfigs[0] = &whConfigOutput{name: "binding.spo.io"}
	whConfigs[1] = &whConfigOutput{name: "recording.spo.io"}
	return whConfigs
}

func (e *e2e) getAllWebhookAttributes() []*whConfigOutput {
	out := getWhConfigs()
	for i := range out {
		out[i].objectSelector = e.getWebhookAttribute(out[i].name, "objectSelector")
		out[i].namespaceSelector = e.getWebhookAttribute(out[i].name, "namespaceSelector")
		out[i].failurePolicy = e.getWebhookAttribute(out[i].name, "failurePolicy")
	}
	return out
}

func (e *e2e) getWebhookAttribute(hook, attr string) string {
	jsonPath := fmt.Sprintf("{.webhooks[?(@.name==%q)].%s}", hook, attr)
	return e.kubectlOperatorNS("get", "MutatingWebhookConfiguration",
		"spo-mutating-webhook-configuration",
		"--output", "jsonpath="+jsonPath)
}
