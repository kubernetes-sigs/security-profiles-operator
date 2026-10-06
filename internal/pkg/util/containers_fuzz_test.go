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

package util

import (
	"errors"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/require"
)

const fuzzStat = "1234 (cmd with ) paren) S 1 1234 1234 0 -1 4194560 100 0 0 0 " +
	"0 0 0 0 20 0 1 0 123456 1234567 89 18446744073709551615"

var errFuzzNotCached = errors.New("not cached")

// FuzzContainerIDForPID feeds arbitrary /proc/<pid>/stat and
// /proc/<pid>/cgroup content into the container ID lookup. A found ID is
// always a 64 digit hex string present in the cgroup content, and a second
// lookup served by the cache returns the same ID.
func FuzzContainerIDForPID(f *testing.F) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, seed := range []struct{ stat, cgroup string }{
		{fuzzStat, "0::/kubepods.slice/cri-containerd-" + id + ".scope\n"},
		{fuzzStat, "12:memory:/docker/" + id + "/docker/" + id + "\n"},
		{fuzzStat, "0::/user.slice\n"},
		{fuzzStat, ""},
		{"1 (a) S", "0::/" + id},
		{"", ""},
		{")", id},
		{"1 (a)) " + fuzzStat, id[:63]},
	} {
		f.Add([]byte(seed.stat), []byte(seed.cgroup))
	}

	f.Fuzz(func(t *testing.T, stat, cgroup []byte) {
		cache := ttlcache.New[string, string]()
		statReader := func(int) ([]byte, error) { return stat, nil }
		cgroupReader := func(int) ([]byte, error) { return cgroup, nil }

		containerID, err := containerIDForPID(cache, 1, statReader, cgroupReader)
		if err != nil {
			require.Empty(t, containerID)

			return
		}

		require.Len(t, containerID, 64)
		require.True(t, ContainerIDRegex.MatchString(containerID))
		require.Contains(t, string(cgroup), containerID)

		failingReader := func(int) ([]byte, error) { return nil, errFuzzNotCached }
		cached, err := containerIDForPID(cache, 1, statReader, failingReader)
		require.NoError(t, err)
		require.Equal(t, containerID, cached)
	})
}

// FuzzProcessStartTime feeds arbitrary /proc/<pid>/stat content into the
// start time parsing, which must never return a negative duration.
func FuzzProcessStartTime(f *testing.F) {
	for _, seed := range []string{
		fuzzStat,
		"1 (a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 -5 0 0",
		"1 (a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9223372036854775807 0 0",
		"1 (a) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 0x10 0 0",
		"1 (a)",
		"1 (a) ",
		")",
		"",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, stat []byte) {
		start, err := processStartTime(1, func(int) ([]byte, error) { return stat, nil })
		if err != nil {
			require.Zero(t, start)

			return
		}

		require.GreaterOrEqual(t, start, time.Duration(0))
	})
}
