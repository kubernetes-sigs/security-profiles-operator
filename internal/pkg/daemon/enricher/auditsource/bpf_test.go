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

	"github.com/stretchr/testify/require"
)

// TestBpfNamesExist asserts that the ring buffer the enricher looks up by name
// exists in the compiled objects of every architecture.
func TestBpfNamesExist(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"bpf/enricher.bpf.o.amd64", "bpf/enricher.bpf.o.arm64"} {
		file, err := elf.Open(path)
		require.NoError(t, err)

		symbols, err := file.Symbols()
		require.NoError(t, err)

		found := false

		for _, symbol := range symbols {
			if symbol.Name == auditLogRingBuf && int(symbol.Section) < len(file.Sections) &&
				file.Sections[symbol.Section].Name == ".maps" {
				found = true
			}
		}

		require.NoError(t, file.Close())
		require.True(t, found, "%s: map %s not found", path, auditLogRingBuf)
	}
}
