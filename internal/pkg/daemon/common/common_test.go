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

package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nxadm/tail"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

func Test_GetSPODNameNonDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "customSPODName")

	require.Equal(t, "customSPODName", GetSPODName())
}

func Test_GetSPODNameDefault(t *testing.T) {
	t.Setenv(config.SPOdNameEnvKey, "")

	require.Equal(t, config.SPOdName, GetSPODName())
}

func Test_AuditTimeToIso(t *testing.T) {
	t.Parallel()

	isoTimestamp, err := AuditTimeToIso("1746611740.574:325")
	require.NoError(t, err)
	require.Equal(t, "2025-05-07T09:55:40.000Z", isoTimestamp)

	_, errInvalid1 := AuditTimeToIso("invalid")
	require.Error(t, errInvalid1)

	_, errInvalid2 := AuditTimeToIso("invalid.invalid")
	require.Error(t, errInvalid2)
}

// TestLogTailConfigKeepsLinesWrittenWhileReading asserts that lines written
// while a partially written line is processed are not skipped, which lost
// bursts of audit lines while the log enricher was busy.
func TestLogTailConfigKeepsLinesWrittenWhileReading(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, []byte("before\n"), 0o600))

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)

	defer file.Close()

	tailFile, err := tail.TailFile(path, LogTailConfig())
	require.NoError(t, err)

	defer tailFile.Cleanup()
	defer tailFile.Stop() //nolint:errcheck // Only stops the tail.

	nextLine := func(timeout time.Duration) string {
		select {
		case line := <-tailFile.Lines:
			return line.Text
		case <-time.After(timeout):
			return ""
		}
	}

	// Following starts at the end of the file once tail opened it.
	for {
		_, err := file.WriteString("ready\n")
		require.NoError(t, err)

		if nextLine(100*time.Millisecond) == "ready" {
			break
		}
	}

	// A line which is still being written, followed by more lines while
	// nothing reads from tail.
	_, err = file.WriteString("partial")
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	_, err = file.WriteString(" line\nfirst\nsecond\n")
	require.NoError(t, err)

	var lines []string

	for len(lines) < 3 {
		line := nextLine(10 * time.Second)
		require.NotEmpty(t, line, "got only %v", lines)

		if line != "ready" {
			lines = append(lines, line)
		}
	}

	require.Equal(t, []string{"partial line", "first", "second"}, lines)
}
