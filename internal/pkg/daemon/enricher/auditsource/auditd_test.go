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

package auditsource

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

//nolint:lll // no need to wrap
const auditdTestLine = `type=SECCOMP msg=audit(1613596317.899:6461): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=2039886 comm="ls" exe="/bin/ls" sig=0 arch=c000003e syscall=3 compat=0 ip=0x7f62dce3d4c7 code=0x7ffc0000`

// waitClosed asserts that log gets closed.
func waitClosed(t *testing.T, log <-chan *types.AuditLine) {
	t.Helper()

	for {
		select {
		case _, ok := <-log:
			if !ok {
				return
			}
		case <-time.After(time.Minute):
			t.Fatal("log not closed")
		}
	}
}

func TestAuditdSourceStartTail(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")
	require.NoError(t, os.WriteFile(path, []byte("old line\n"), 0o600))

	sut := NewAuditdSource(logr.Discard())
	sut.path = path

	require.NoError(t, sut.TailErr(), "no error before the tail started")

	log, err := sut.StartTail()
	require.NoError(t, err)

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	t.Cleanup(func() { file.Close() })

	// Only the audit lines written from now on are forwarded.
	_, err = file.WriteString("not an audit line\n" + auditdTestLine + "\n")
	require.NoError(t, err)

	select {
	case line := <-log:
		require.Equal(t, types.AuditTypeSeccomp, line.AuditType)
		require.Equal(t, 2039886, line.ProcessID)
		require.Equal(t, "/bin/ls", line.Executable)
	case <-time.After(time.Minute):
		t.Fatal("no audit line received")
	}

	require.NoError(t, sut.TailErr())

	sut.Stop()
	sut.Stop()

	waitClosed(t, log)
}

// TestAuditdSourceStopReleasesForward asserts that the goroutine forwarding
// the lines does not wait forever for a consumer which is gone.
func TestAuditdSourceStopReleasesForward(t *testing.T) {
	t.Parallel()

	sut := NewAuditdSource(logr.Discard())

	lines := make(chan string, 1)
	log := make(chan *types.AuditLine)
	done := make(chan struct{})

	go func() {
		defer close(done)

		sut.forward(lines, log)
	}()

	lines <- auditdTestLine

	// Nobody reads the line.
	sut.Stop()

	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("forwarding the lines did not stop")
	}

	_, open := <-log
	require.False(t, open)
}

// TestAuditdSourceForwardEndsWithLines asserts that the log ends once the
// tail ended.
func TestAuditdSourceForwardEndsWithLines(t *testing.T) {
	t.Parallel()

	sut := NewAuditdSource(logr.Discard())

	lines := make(chan string)
	log := make(chan *types.AuditLine, 1)

	close(lines)
	sut.forward(lines, log)

	_, open := <-log
	require.False(t, open)
}
