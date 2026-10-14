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
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func (e *e2e) testCaseProfilingChange([]string) {
	e.restoreSpodSpec()

	e.logf("Change profiling in spod")
	e.patchSpod(`{"spec":{"enableProfiling": true}}`)

	// The daemon runs with the rolled out spec, testCaseProfilingHTTP checks
	// that the endpoint answers.
	e.Equal("true", e.spodEnv(config.ProfilingEnvKey))
}

func (e *e2e) testCaseProfilingHTTP([]string) {
	e.logf("Test profiling HTTP version")

	e.restoreSpodSpec()

	e.logf("Enable spod profiling to test endpoint HTTP version")
	e.patchSpod(`{"spec":{"enableProfiling": true}}`)

	output := e.getProfilingHTTPVersion()
	e.assertHTTP11(output)
}

// getProfilingHTTPVersion returns the HTTP version the profiling endpoint
// answers with, moving on to the next spod pod with every attempt.
func (e *e2e) getProfilingHTTPVersion() string {
	attempt := 0

	return e.retryPodCMD(func() (string, error) {
		endpoint, err := e.profilingEndpoint(attempt)
		attempt++

		if err != nil {
			return "", err
		}

		return curlHTTPVerCMD + endpoint, nil
	})
}

// profilingEndpoint returns the profiling endpoint of a spod pod, picked by
// the attempt. While the pods restart, the lookup fails instead of the test,
// so that the caller retries.
func (e *e2e) profilingEndpoint(attempt int) (string, error) {
	output, err := e.kubectlCommand(
		"-n", config.OperatorName, "get", "pods", "-l", "name=spod", "-o", "json",
	)
	if err != nil {
		return "", fmt.Errorf("listing the spod pods: %w", err)
	}

	pods := &corev1.PodList{}
	if err := json.Unmarshal([]byte(output), pods); err != nil {
		return "", fmt.Errorf("decoding the spod pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return "", errors.New("no spod pods")
	}

	pod := &pods.Items[attempt%len(pods.Items)]
	if pod.Status.PodIP == "" {
		return "", fmt.Errorf("pod %s has no IP yet", pod.Name)
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name != config.OperatorName {
			continue
		}

		for _, env := range pod.Spec.Containers[i].Env {
			if env.Name == config.ProfilingPortEnvKey && env.Value != "" {
				return "http://" + pod.Status.PodIP + ":" + env.Value + "/debug/pprof/heap", nil
			}
		}
	}

	return "", fmt.Errorf("pod %s has no profiling port", pod.Name)
}
