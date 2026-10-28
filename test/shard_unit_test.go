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
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseTestShard(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value   string
		want    testShard
		wantErr bool
	}{
		{value: "", want: testShard{}},
		{value: "1/1", want: testShard{index: 1, total: 1}},
		{value: "2/3", want: testShard{index: 2, total: 3}},
		{value: "3/3", want: testShard{index: 3, total: 3}},
		{value: "0/3", wantErr: true},
		{value: "4/3", wantErr: true},
		{value: "1/0", wantErr: true},
		{value: "1", wantErr: true},
		{value: "a/3", wantErr: true},
		{value: "1/b", wantErr: true},
	} {
		got, err := parseTestShard(tc.value)
		if tc.wantErr {
			require.Error(t, err, tc.value)

			continue
		}

		require.NoError(t, err, tc.value)
		require.Equal(t, tc.want, got, tc.value)
	}
}

func TestAssignTestShards(t *testing.T) {
	t.Parallel()

	weights := []time.Duration{
		10 * time.Second, 60 * time.Second, 30 * time.Second, 30 * time.Second,
		0, 20 * time.Second, 50 * time.Second, 0,
	}

	for total := 1; total <= len(weights)+1; total++ {
		shards := assignTestShards(weights, total)
		require.Len(t, shards, len(weights))

		loads := make([]time.Duration, total)

		for i, shard := range shards {
			require.GreaterOrEqual(t, shard, 1)
			require.LessOrEqual(t, shard, total)

			loads[shard-1] += weights[i]
		}

		// Every weight is in exactly one shard, and the shards differ by at
		// most the heaviest weight.
		var sum time.Duration
		for _, load := range loads {
			sum += load
		}

		require.Equal(t, 200*time.Second, sum)
		require.LessOrEqual(t, slices.Max(loads)-slices.Min(loads), time.Minute)

		require.Equal(
			t,
			shards,
			assignTestShards(weights, total),
			"the assignment is deterministic",
		)
	}

	// The heaviest first, each to the lightest shard, the first of equal ones.
	require.Equal(t, []int{1, 1, 3, 3, 3, 2, 2, 3}, assignTestShards(weights, 3))
}

func TestTestNamePattern(t *testing.T) {
	t.Parallel()

	const (
		method    = "TestSuite/TestSecurityProfilesOperator"
		enricher  = method + "/cluster-wide:_Log_Enricher"
		namespace = method + "/namespaced:_Log_Enricher"
		spod      = method + "/cluster-wide:_SPOD:_Change_verbosity"
		selinux   = method + "/cluster-wide:_SELinux:_base_case_(install_policy,_run_pod_and_delete)"
	)

	// The skip pattern of the SELinux suite of the Fedora CI job.
	fedoraSkip := `//cluster-wide:_(Log_Enricher|SPOD:_(Change|Enable|Profiling)` +
		`|Seccomp:_Verify_profile_recording_logs)`

	for _, tc := range []struct {
		skip    string
		name    string
		skipped bool
	}{
		{name: enricher, skipped: false},
		{skip: fedoraSkip, name: enricher, skipped: true},
		{skip: fedoraSkip, name: namespace, skipped: false},
		{skip: fedoraSkip, name: spod, skipped: true},
		{skip: fedoraSkip, name: selinux, skipped: false},
		// A partial match skips nothing.
		{skip: fedoraSkip, name: method, skipped: false},
		{skip: `^TestSuite$/^TestSecurityProfilesOperator_Flaky$`, name: enricher, skipped: false},
		{skip: `^TestSuite$/^TestSecurityProfilesOperator$`, name: enricher, skipped: true},
		{skip: `Other|^TestSuite$/^TestSecurityProfilesOperator$/Log`, name: enricher, skipped: true},
		{skip: `Other|^TestSuite$/^TestSecurityProfilesOperator$/Log`, name: spod, skipped: false},
		// Slashes and bars in brackets and parentheses belong to the element.
		{skip: `//(namespaced|cluster-wide):_[/|]?Log`, name: namespace, skipped: true},
		{skip: `//cluster-wide:_SELinux:_base_case_\(install`, name: selinux, skipped: true},
	} {
		skip, err := compileTestNamePattern(tc.skip)
		require.NoError(t, err, tc.skip)

		require.Equal(
			t,
			tc.skipped,
			testSkipped(tc.name, skip),
			"skip %q name %q",
			tc.skip,
			tc.name,
		)
	}

	_, err := compileTestNamePattern(`//(`)
	require.Error(t, err)
}

// TestTestCaseShardsRerun checks that a test case which gotestsum retries with
// a -test.run pattern of only that test case lands in the shard which failed
// it, and that the test cases which -test.skip skips weigh nothing.
//
//nolint:paralleltest // changes the flags of the testing package
func TestTestCaseShardsRerun(t *testing.T) {
	const method = "TestSuite/TestSecurityProfilesOperator_Flaky"

	names := []string{
		method + "/cluster-wide:_SELinux:_Metrics_(update,_delete)",
		method + "/cluster-wide:_SPOD:_Test_Metrics_HTTP_version",
		method + "/cluster-wide:_Seccomp:_Verify_profile_binding:_image",
		method + "/cluster-wide:_Seccomp:_Verify_profile_binding:_wildcard",
		method + "/cluster-wide:_Seccomp:_Verify_profile_recording_logs:_deployment_scale_up_and_down",
		method + "/namespaced:_SPOD:_Test_Metrics_HTTP_version",
	}
	durations := []time.Duration{
		114 * time.Second, 14 * time.Second, 7 * time.Second,
		7 * time.Second, 204 * time.Second, 14 * time.Second,
	}

	for _, name := range []string{"test.run", "test.skip"} {
		value := flag.Lookup(name).Value.String()

		t.Cleanup(func() {
			require.NoError(t, flag.Set(name, value))
		})
	}

	require.NoError(t, flag.Set("test.skip", ""))
	require.NoError(t, flag.Set("test.run", `^TestSuite$/^TestSecurityProfilesOperator_Flaky$`))

	const total = 3

	shards := testCaseShards(names, durations, total)
	require.Equal(t, assignTestShards(durations, total), shards)

	for _, name := range names {
		// gotestsum quotes each element of the name of the failed test.
		elements := strings.Split(name, "/")
		for i := range elements {
			elements[i] = "^" + regexp.QuoteMeta(elements[i]) + "$"
		}

		require.NoError(t, flag.Set("test.run", strings.Join(elements, "/")))
		require.Equal(t, shards, testCaseShards(names, durations, total), "rerun of %s", name)
	}

	require.NoError(
		t,
		flag.Set("test.skip", "//cluster-wide:_Seccomp:_Verify_profile_recording_logs"),
	)

	skipped := slices.Clone(durations)
	skipped[4] = 0
	require.Equal(t, assignTestShards(skipped, total), testCaseShards(names, durations, total))
}

func TestSubTestName(t *testing.T) {
	t.Parallel()

	require.Equal(t,
		"cluster-wide:_SELinux:_Metrics_(update,_delete)",
		subTestName("cluster-wide: SELinux: Metrics (update, delete)"),
	)
}
