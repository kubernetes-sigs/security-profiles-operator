//go:build linux && !no_bpf

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

package bpfrecorder

import (
	"bytes"
	"debug/elf"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

// bpfSymbol is a symbol of a compiled BPF object.
type bpfSymbol struct {
	section string
	typ     elf.SymType
}

// bpfSymbols returns the symbols of a compiled BPF object by name.
func bpfSymbols(t *testing.T, object []byte) map[string]bpfSymbol {
	t.Helper()

	file, err := elf.NewFile(bytes.NewReader(object))
	require.NoError(t, err)

	symbols, err := file.Symbols()
	require.NoError(t, err)

	result := map[string]bpfSymbol{}

	for _, symbol := range symbols {
		if int(symbol.Section) >= len(file.Sections) {
			continue
		}

		result[symbol.Name] = bpfSymbol{
			section: file.Sections[symbol.Section].Name,
			typ:     elf.ST_TYPE(symbol.Info),
		}
	}

	return result
}

// TestBpfNamesExist asserts that every map, global variable and program the
// recorder looks up by name exists in the compiled objects, so that renaming
// one in recorder.bpf.c without the Go code fails here and not only when the
// recorder starts.
func TestBpfNamesExist(t *testing.T) {
	t.Parallel()

	for arch, object := range map[string][]byte{"amd64": bpfAmd64, "arm64": bpfArm64} {
		symbols := bpfSymbols(t, object)

		for _, name := range bpfMapNames {
			symbol, ok := symbols[name]
			require.True(t, ok, "%s: map %s not found", arch, name)
			require.Equal(t, ".maps", symbol.section, "%s: %s is no map", arch, name)
		}

		for _, name := range bpfGlobalNames {
			symbol, ok := symbols[name]
			require.True(t, ok, "%s: global variable %s not found", arch, name)
			require.Equal(t, elf.STT_OBJECT, symbol.typ, "%s: %s is no variable", arch, name)
			require.Contains(t, []string{".rodata", ".data", ".bss"}, symbol.section,
				"%s: %s is no global variable", arch, name)
		}

		for _, name := range slices.Concat(baseHooks, appArmorHooks, procCacheHooks) {
			symbol, ok := symbols[name]
			require.True(t, ok, "%s: program %s not found", arch, name)
			require.Equal(t, elf.STT_FUNC, symbol.typ, "%s: %s is no program", arch, name)
			require.NotEqual(t, ".text", symbol.section, "%s: %s is no program", arch, name)
		}
	}
}
