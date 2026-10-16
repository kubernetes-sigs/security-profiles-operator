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
	"strings"
	"time"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	webhookDeployment = "security-profiles-operator-webhook"
	// webhookDownBindingNamespace has the binding webhook enabled.
	webhookDownBindingNamespace = "spo-webhook-down-binding"
	// webhookDownOtherNamespace has no webhook of the operator enabled.
	webhookDownOtherNamespace = "spo-webhook-down-other"
)

// webhookDownPodArgs are the kubectl arguments to create a pod in the
// namespace.
func webhookDownPodArgs(name, namespace string) []string {
	return []string{
		"run", name, "--namespace", namespace, "--restart=Never",
		"--image=quay.io/security-profiles-operator/test-hello-world:latest",
	}
}

// testCaseWebhookDown checks that the binding webhook fails closed for the
// namespaces it applies to while it is down, without blocking pods in other
// namespaces, and that it admits pods again once it is back.
func (e *e2e) testCaseWebhookDown([]string) {
	for _, namespace := range []string{webhookDownBindingNamespace, webhookDownOtherNamespace} {
		e.kubectl("create", "namespace", namespace)
		e.kubectlCleanup("namespace", namespace)
	}

	e.enableBindingHookInNs(webhookDownBindingNamespace)

	replicas := e.deploymentReplicas(webhookDeployment)
	managerReplicas := e.deploymentReplicas(config.OperatorName)

	// Leave a working manager and webhook behind, also if the test fails.
	e.cleanup(func() {
		e.scaleDeployment(config.OperatorName, managerReplicas)
		e.scaleDeployment(webhookDeployment, replicas)
	})

	// The manager restores the webhook deployment, so it has to be gone
	// before the webhook gets scaled down. A terminating manager may still
	// reconcile and roll the webhook out again.
	e.logf("Scaling the manager down")
	e.kubectlOperatorNS("scale", "deployment", config.OperatorName, "--replicas=0")
	e.waitForNoPods(config.OperatorName)

	e.logf("Scaling the webhook down")
	e.kubectlOperatorNS("scale", "deployment", webhookDeployment, "--replicas=0")
	e.waitForNoPods(webhookDeployment)

	e.logf("Checking that the binding webhook rejects pods while it is down")

	_, err := e.kubectlCommand(webhookDownPodArgs("webhook-down", webhookDownBindingNamespace)...)
	e.Require().Error(err, "a pod got admitted without the binding webhook")
	// The error names the pod, which contains "webhook" as well, so check for
	// the admission failure of the binding webhook itself.
	e.Contains(err.Error(), `failed calling webhook "binding.spo.io"`)

	e.logf("Checking that pods of other namespaces are still admitted")

	_, err = e.kubectlCommand(webhookDownPodArgs("webhook-down", webhookDownOtherNamespace)...)
	e.Require().NoError(err)

	e.logf("Scaling the manager and the webhook up again")
	e.kubectlOperatorNS("scale", "deployment", config.OperatorName, "--replicas="+managerReplicas)
	e.kubectlOperatorNS("scale", "deployment", webhookDeployment, "--replicas="+replicas)

	for _, deployment := range []string{config.OperatorName, webhookDeployment} {
		e.kubectlOperatorNS(
			"rollout", "status", "deployment", deployment, "--timeout", defaultLongOpTimeout,
		)
	}

	e.logf("Checking that the binding webhook admits pods again")
	e.eventually(time.Minute, defaultPollInterval, func() error {
		_, err := e.kubectlCommand(webhookDownPodArgs("webhook-up", webhookDownBindingNamespace)...)
		if err != nil && strings.Contains(err.Error(), "AlreadyExists") {
			return nil
		}

		return err
	})
}

// waitForNoPods waits until no pod of the deployment in the operator
// namespace is left, the pods carry the name of their deployment as label.
func (e *e2e) waitForNoPods(deployment string) {
	e.requireEventually(defaultWaitDuration, defaultPollInterval, func() error {
		pods := e.kubectlOperatorNS("get", "pods", "-l", "name="+deployment, "-o", "name")
		if pods != "" {
			return fmt.Errorf("pods of %s still running: %s", deployment, pods)
		}

		return nil
	})
}

// deploymentReplicas returns the replicas of the deployment in the operator
// namespace.
func (e *e2e) deploymentReplicas(name string) string {
	return e.kubectlOperatorNS("get", "deployment", name, "-o", "jsonpath={.spec.replicas}")
}

// scaleDeployment scales the deployment in the operator namespace and only
// logs a failure, for use in cleanups.
func (e *e2e) scaleDeployment(name, replicas string) {
	if _, err := e.kubectlCommand(
		"--namespace", config.OperatorName,
		"scale", "deployment", name, "--replicas="+replicas,
	); err != nil {
		e.logf("Unable to scale deployment %s up again: %v", name, err)
	}
}
