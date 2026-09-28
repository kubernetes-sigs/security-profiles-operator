//go:build linux && !no_bpf && (amd64 || arm64)

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
	"debug/elf"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/enricher/types"
)

// TestBpfNamesExist asserts that the maps the enricher looks up by name exist
// in the compiled objects of every architecture.
func TestBpfNamesExist(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"bpf/enricher.bpf.o.amd64", "bpf/enricher.bpf.o.arm64"} {
		file, err := elf.Open(path)
		require.NoError(t, err)

		symbols, err := file.Symbols()
		require.NoError(t, err)

		found := map[string]bool{}

		for _, symbol := range symbols {
			if int(symbol.Section) < len(file.Sections) &&
				file.Sections[symbol.Section].Name == ".maps" {
				found[symbol.Name] = true
			}
		}

		require.NoError(t, file.Close())

		for _, name := range []string{auditLogRingBuf, lostEventsMap} {
			require.True(t, found[name], "%s: map %s not found", path, name)
		}
	}
}

// TestBpfSourceStopReleasesForward asserts that the goroutine forwarding the
// events does not wait forever for a consumer which is gone.
func TestBpfSourceStopReleasesForward(t *testing.T) {
	t.Parallel()

	sut, err := NewBpfSource(logr.Discard())
	if err != nil {
		t.Skip(err.Error())
	}

	events := make(chan []byte, 1)
	log := make(chan *types.AuditLine)
	done := make(chan struct{})

	go func() {
		defer close(done)

		sut.forward(events, log)
	}()

	events <- []byte{
		1, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0,
		'o', 0, 'c', 0, 'n', 0,
	}

	// Nobody reads the line.
	sut.Stop()

	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("forwarding the events did not stop")
	}

	_, open := <-log
	require.False(t, open)
}
