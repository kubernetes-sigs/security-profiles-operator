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

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	spoutil "sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func (e *e2e) testCaseProfilingChange([]string) {
	e.logf("Change profiling in spod")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableProfiling": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")
	e.kubectlOperatorNS("rollout", "status", "ds", "spod", "--timeout", defaultBpfRecorderOpTimeout)

	logs := e.kubectlOperatorNS(
		"logs",
		"ds/spod",
		"security-profiles-operator",
	)

	e.Contains(logs, "Profiling support enabled: true")
}

func (e *e2e) testCaseProfilingHTTP([]string) {
	e.selinuxOnlyTestCase()
	e.logf("Test profiling HTTP version")

	e.logf("Enable spod profiling to test endpoint HTTP version")
	e.kubectlOperatorNS("patch", "spod", "spod", "-p", `{"spec":{"enableProfiling": true}}`, "--type=merge")
	time.Sleep(defaultWaitTime)

	e.waitInOperatorNSFor("condition=ready", "spod", "spod")

	output := e.getProfilingHTTPVersion()
	e.Contains(output, "1.1\n")
}

func (e *e2e) getProfilingEndpoint(i int) string {
	podName := e.kubectlOperatorNS("get", "pods", "-l", "name=spod", "-o",
		fmt.Sprintf("jsonpath={.items[%d].metadata.name}", i))
	podIP := e.kubectlOperatorNS("get", "pods", "-l", "name=spod", "-o",
		fmt.Sprintf("jsonpath={.items[?(@.metadata.name=='%s')].status.podIP}", podName))
	podPort := e.kubectlOperatorNS("get", "pods", "-l", "name=spod", "-o",
		fmt.Sprintf("jsonpath={.items[?(@.metadata.name=='%s')]"+
			".spec.containers[?(@.name=='security-profiles-operator')]"+
			".env[?(@.name=='SPO_PROFILING_PORT')].value}", podName))
	return "http://" + podIP + ":" + podPort + "/debug/pprof/heap"
}

// This function is inspired by e2e.runAndRetryPodCMD().
func (e *e2e) getProfilingHTTPVersion() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}

	nPodsOutput := e.kubectlOperatorNS("get", "daemonsets", "spod", "-o",
		"jsonpath={.status.numberAvailable}")
	nPods, err := strconv.Atoi(nPodsOutput)
	if err != nil {
		e.Failf("could not get size of spod daemonset", "error: %s", err)
	}
	index := 0

	// Sometimes the endpoint does not output anything in CI. We fix
	// that by retrying the endpoint several times.
	var output string
	if err := spoutil.Retry(func() error {
		profilingEndpoint := e.getProfilingEndpoint(index)
		profilingCurlCMD := curlHTTPVerCMD + profilingEndpoint
		output = e.kubectlRunOperatorNS("pod-"+string(b), "--", "bash", "-c", profilingCurlCMD)
		if len(strings.Split(output, "\n")) > 1 {
			return nil
		}
		output = ""
		return errors.New("no output from profiling curl command")
	}, func(err error) bool {
		e.logf("retry on error: %s", err)
		if index < nPods {
			index++
			return true
		}
		return false
	}); err != nil {
		e.Failf("unable to get profiling endpoint http version", "error: %s", err)
	}
	return output
}
