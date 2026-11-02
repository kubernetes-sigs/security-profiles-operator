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
	"flag"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// feature is a switch of the suite which a test case needs, it skips itself
// without it.
type feature uint

const (
	needsSeccomp feature = 1 << iota
	needsSelinux
	needsLogEnricher
	needsBpfLogEnricher
	needsJSONEnricher
	needsBpfRecorder
	needsWebhookConfig
	needsWebhookHTTP
	needsMetricsHTTP
	needsOpenShift
	needsNoOpenShift
)

// testCaseCost is what the shards know about a test case without running it.
type testCaseCost struct {
	// duration is about how long the test case took in CI, in the slowest
	// environment which runs it.
	duration time.Duration
	// needs are the switches without which the test case skips itself.
	needs feature
}

// defaultTestCaseDuration is the duration of a test case without a cost.
const defaultTestCaseDuration = 30 * time.Second

// testCaseCosts balance the shards, see E2E_SHARD, keyed by the description
// of the test case. Every test case runs in exactly one shard, so a duration
// which is off only makes the shards less balanced. Needs which are stricter
// than the test case's own skips keep it from running at all, see
// anyRunnable. TestShardCosts checks that every test case has a cost.
var testCaseCosts = map[string]testCaseCost{
	"Seccomp: Verify default and example profiles":    {6 * time.Second, needsSeccomp},
	"Seccomp: Verify base profile merge":              {6 * time.Second, needsSeccomp},
	"Seccomp: Verify runtime format OCI base profile": {37 * time.Second, needsSeccomp},
	"Seccomp: Allowed syscalls":                       {104 * time.Second, needsSeccomp},
	"Seccomp: Delete profiles":                        {122 * time.Second, needsSeccomp},
	reDeployDescription:                               {28 * time.Second, needsSeccomp},
	"Log Enricher":                                    {62 * time.Second, needsLogEnricher},
	"Log Enricher (BPF Source)": {
		defaultTestCaseDuration,
		needsBpfLogEnricher,
	},
	"JSON Enricher":                    {60 * time.Second, needsJSONEnricher},
	"JSON Enricher: exec of a command": {45 * time.Second, needsJSONEnricher},
	"Log Enricher with filters":        {67 * time.Second, needsLogEnricher},
	"JSON Enricher File Options":       {122 * time.Second, needsJSONEnricher},
	"SELinux: base case (install policy, run pod and delete)": {
		143 * time.Second, needsSelinux,
	},
	"SELinux: base case (install policy, run pod and delete) for the raw CR": {
		83 * time.Second, needsSelinux,
	},
	"SELinux: non-default template":      {42 * time.Second, needsSelinux},
	"SELinux: Metrics (update, delete)":  {114 * time.Second, needsSelinux},
	"SPOD: Update SELinux flag":          {73 * time.Second, needsSelinux},
	"SPOD: Change verbosity":             {23 * time.Second, 0},
	"SPOD: Change profiling":             {23 * time.Second, 0},
	"SPOD: Profiling server protocol":    {31 * time.Second, 0},
	"SPOD: Enable memory optimization":   {24 * time.Second, 0},
	"SPOD: Change resource requirements": {25 * time.Second, 0},
	"Seccomp: make sure statuses for profiles with long names can be listed": {
		4 * time.Second, 0,
	},
	"SPOD: Change webhook config":               {10 * time.Second, needsWebhookConfig},
	"SPOD: Enable profile recorder":             {18 * time.Second, 0},
	"TLS: Verify TLS profile on OpenShift":      {defaultTestCaseDuration, needsOpenShift},
	"Selinux: Verify profile binding: image":    {55 * time.Second, needsSelinux},
	"Selinux: Verify profile binding: wildcard": {47 * time.Second, needsSelinux},
	"Selinux: Verify profile binding: namespace not enabled": {
		51 * time.Second, needsSelinux,
	},
	"Selinux: Verify the policy can be marked as permissive: enforcing": {
		50 * time.Second, needsSelinux,
	},
	"Selinux: Verify the policy can be marked as permissive: permissive": {
		88 * time.Second, needsSelinux,
	},
	"Selinux: Verify that the SPOD can deny permissive policies": {37 * time.Second, needsSelinux},
	"Selinux: Verify the policy can be marked as permissive: disabled": {
		13 * time.Second, needsSelinux,
	},
	"Selinux: Verify SELinux profile recording logs: static pod": {
		96 * time.Second, needsLogEnricher | needsSelinux,
	},
	"Selinux: Verify SELinux profile recording logs: multiple containers": {
		103 * time.Second, needsLogEnricher | needsSelinux,
	},
	"Selinux: Verify SELinux profile recording logs: deployment": {
		51 * time.Second, needsLogEnricher | needsSelinux,
	},
	"Selinux: Verify SELinux profile recording logs: namespace not enabled": {
		20 * time.Second, needsLogEnricher | needsSelinux,
	},
	"profile merging: seccomp bpf":  {96 * time.Second, needsBpfRecorder},
	"profile merging: seccomp logs": {177 * time.Second, needsLogEnricher},
	"profile merging: selinux logs": {
		115 * time.Second,
		needsLogEnricher | needsSelinux,
	},
	"profile merging: selinux logs disabled": {
		99 * time.Second,
		needsLogEnricher | needsSelinux,
	},
	"Seccomp: Metrics":                                   {10 * time.Second, needsSeccomp},
	"SPOD: Test webhook HTTP version":                    {24 * time.Second, needsWebhookHTTP},
	"SPOD: Test Metrics HTTP version":                    {14 * time.Second, needsMetricsHTTP},
	"Seccomp: Verify profile binding: image":             {7 * time.Second, needsSeccomp},
	"Seccomp: Verify profile binding: wildcard":          {7 * time.Second, needsSeccomp},
	"Seccomp: Verify profile recording logs: static pod": {40 * time.Second, needsLogEnricher},
	"Seccomp: Verify profile recording logs: multiple containers": {
		57 * time.Second, needsLogEnricher,
	},
	"Seccomp: Verify profile recording logs: specific container": {
		77 * time.Second, needsLogEnricher,
	},
	"Seccomp: Verify profile recording logs: deployment": {79 * time.Second, needsLogEnricher},
	"Seccomp: Verify profile recording logs: finalizers": {42 * time.Second, needsLogEnricher},
	"Seccomp: Verify profile recording logs: deployment scale up and down": {
		204 * time.Second, needsLogEnricher,
	},
	"Seccomp: Verify profile recording logs: memory optimization": {
		64 * time.Second, needsLogEnricher,
	},
	"Seccomp: Verify profile recording bpf: kubectl run": {30 * time.Second, needsBpfRecorder},
	"Seccomp: Verify profile recording bpf: static pod":  {22 * time.Second, needsBpfRecorder},
	"Seccomp: Verify profile recording bpf: multiple containers": {
		22 * time.Second, needsBpfRecorder,
	},
	"Seccomp: Verify profile recording bpf: deployment":       {22 * time.Second, needsBpfRecorder},
	"Seccomp: Verify profile recording bpf: parallel":         {16 * time.Second, needsBpfRecorder},
	"Seccomp: Verify profile recording bpf: select container": {53 * time.Second, needsBpfRecorder},
	"Seccomp: Verify profile recording bpf: memory optimization": {
		147 * time.Second, needsBpfRecorder,
	},
	"SPOD: Upgrade from the previous release": {63 * time.Second, needsSeccomp | needsNoOpenShift},
	"SPOD: Webhook down":                      {42 * time.Second, 0},
}

// has reports whether the suite runs with all the switches.
func (e *e2e) has(needs feature) bool {
	openShift := strings.EqualFold(clusterType, clusterTypeOpenShift)

	for f, enabled := range map[feature]bool{
		needsSeccomp:        e.testSeccomp,
		needsSelinux:        e.selinuxEnabled,
		needsLogEnricher:    e.logEnricherEnabled,
		needsBpfLogEnricher: e.bpfEnricherEnabled,
		needsJSONEnricher:   e.jsonEnricherEnabled,
		needsBpfRecorder:    e.bpfRecorderEnabled,
		needsWebhookConfig:  e.testWebhookConfig,
		needsWebhookHTTP:    e.testWebhookHTTP,
		needsMetricsHTTP:    e.testMetricsHTTP,
		needsOpenShift:      openShift,
		needsNoOpenShift:    !openShift,
	} {
		if needs&f != 0 && !enabled {
			return false
		}
	}

	return true
}

// anyRunnable reports whether one of the test cases of the current suite
// method for the operator of the prefix runs: it has the switches it needs,
// see testCaseCosts, the -test.skip flag does not skip it and the -test.run
// flag selects it, like a retry of a single test case by gotestsum. The others
// skip themselves or do not run, which is not worth deploying the operator
// for. Unlike testCaseShards, which assigns the test cases to the shards, this
// may depend on -test.run.
func (e *e2e) anyRunnable(prefix string, testCases []testCase) bool {
	return e.runnable(prefix, testCases) > 0
}

// runnable returns how many of the test cases run, see anyRunnable.
func (e *e2e) runnable(prefix string, testCases []testCase) int {
	skip := testFlagPattern("test.skip")
	run := testFlagPattern("test.run")
	method := e.T().Name()
	count := 0

	for _, tc := range testCases {
		name := method + "/" + subTestName(prefix+": "+tc.description)
		if e.has(testCaseCosts[tc.description].needs) &&
			!testSkipped(name, skip) && testSelected(name, run) {
			count++
		}
	}

	return count
}

// shardTestCases returns the test cases of the current suite method for the
// cluster wide and the namespaced operator which run in the shard of the
// suite, all of them without one. The shards get the test cases by their
// expected duration, see testCaseShards, with the ones which skip themselves
// counting as nothing.
func (e *e2e) shardTestCases() (clusterWide, namespaced []testCase) {
	quarantined := e.runsQuarantinedTests()
	clusterWide = slices.DeleteFunc(e.testCases(), func(tc testCase) bool {
		return tc.flaky != quarantined
	})

	if !e.skipNamespacedTests {
		namespaced = e.namespacedTestCases(clusterWide)
	}

	if e.shard.total == 0 {
		return clusterWide, namespaced
	}

	method := e.T().Name()
	names := make([]string, 0, len(clusterWide)+len(namespaced))
	durations := make([]time.Duration, 0, len(clusterWide)+len(namespaced))

	add := func(prefix string, testCases []testCase) {
		for _, tc := range testCases {
			cost, ok := testCaseCosts[tc.description]
			if !ok {
				cost.duration = defaultTestCaseDuration
			}

			if !e.has(cost.needs) {
				cost.duration = 0
			}

			names = append(names, method+"/"+subTestName(prefix+": "+tc.description))
			durations = append(durations, cost.duration)
		}
	}

	add("cluster-wide", clusterWide)
	add("namespaced", namespaced)

	shards := testCaseShards(names, durations, e.shard.total)

	inShard := func(offset int, testCases []testCase) []testCase {
		var result []testCase

		for i, tc := range testCases {
			if shards[offset+i] == e.shard.index {
				result = append(result, tc)
			}
		}

		return result
	}

	return inShard(0, clusterWide), inShard(len(clusterWide), namespaced)
}

// TestShardCosts checks that every test case has a cost to balance the shards
// with, and that every cost belongs to a test case.
//
//nolint:paralleltest // the suite does not run in parallel either
func TestShardCosts(t *testing.T) {
	descriptions := map[string]bool{}

	for _, tc := range (&e2e{}).testCases() {
		descriptions[tc.description] = true

		if _, ok := testCaseCosts[tc.description]; !ok {
			t.Errorf("no cost in testCaseCosts for test case %q", tc.description)
		}
	}

	for description := range testCaseCosts {
		if !descriptions[description] {
			t.Errorf("cost in testCaseCosts for unknown test case %q", description)
		}
	}
}

// TestAnyRunnable checks that a test case without its switches, or which the
// -test.skip flag skips or the -test.run flag does not select, does not count
// as runnable.
//
//nolint:paralleltest // it sets the -test.run and -test.skip flags
func TestAnyRunnable(t *testing.T) {
	for _, name := range []string{"test.run", "test.skip"} {
		value := flag.Lookup(name).Value.String()

		t.Cleanup(func() {
			require.NoError(t, flag.Set(name, value))
		})
		require.NoError(t, flag.Set(name, ""))
	}

	e := &e2e{}
	e.SetT(t)

	bpf := []testCase{{description: "Seccomp: Verify profile recording bpf: parallel"}}
	require.False(t, e.anyRunnable("cluster-wide", bpf), "without the switch")

	e.bpfRecorderEnabled = true
	require.True(t, e.anyRunnable("cluster-wide", bpf))

	// Only the test cases with their switches count.
	mixed := append(
		slices.Clone(bpf),
		testCase{description: "Seccomp: Verify profile recording logs: deployment"},
	)
	require.Equal(t, 1, e.runnable("cluster-wide", mixed))

	require.NoError(
		t,
		flag.Set("test.skip", "/cluster-wide:_Seccomp:_Verify_profile_recording_bpf"),
	)
	require.False(t, e.anyRunnable("cluster-wide", bpf), "skipped by -test.skip")
	require.True(t, e.anyRunnable("namespaced", bpf), "other prefix")
	require.NoError(t, flag.Set("test.skip", ""))

	// A retry of a namespaced test case only, the way gotestsum quotes it.
	require.NoError(t, flag.Set("test.run",
		`^TestAnyRunnable$/^namespaced:_Seccomp:_Verify_profile_recording_bpf:_parallel$`))
	require.False(t, e.anyRunnable("cluster-wide", bpf), "not selected by -test.run")
	require.True(t, e.anyRunnable("namespaced", bpf), "selected by -test.run")

	// A pattern of the suite method only selects all of its test cases.
	require.NoError(t, flag.Set("test.run", `^TestAnyRunnable$`))
	require.True(t, e.anyRunnable("cluster-wide", bpf), "selected by the parent")
}
