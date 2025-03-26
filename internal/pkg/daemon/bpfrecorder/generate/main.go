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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/blang/semver/v4"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/types"
)

const header = `//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package bpfrecorder

import _ "embed"

//go:embed bpf/recorder.bpf.o.amd64
var bpfAmd64 []byte
//go:embed bpf/recorder.bpf.o.arm64
var bpfArm64 []byte

`

const (
	baseDir     = "internal/pkg/daemon/bpfrecorder/"
	generatedGo = baseDir + "generated.go"
	btfDir      = baseDir + "btf"
	docsFile    = "bpf-support.md"
	docsHeader  = "The following Kernels are supported to run the BPF recorder " +
		"beside those which already expose `/sys/kernel/btf/vmlinux`. " +
		"Please note that at least a Linux kernel version 5.8 is required " +
		"to use the bpf recorder.\n\n"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	builder := &strings.Builder{}

	builder.WriteString(header)

	if err := generateBtf(builder); err != nil {
		return fmt.Errorf("generate btf: %w", err)
	}

	//nolint:gosec // permissions are fine
	if err := os.WriteFile(
		generatedGo, []byte(builder.String()), 0o644,
	); err != nil {
		return fmt.Errorf("writing generated object: %w", err)
	}

	if err := exec.Command("go", "fmt", generatedGo).Run(); err != nil {
		return fmt.Errorf("format go code: %w", err)
	}

	return nil
}

func generateBtf(builder *strings.Builder) error {
	builder.WriteString("var btfJSON = `")

	btfs := types.Btf{}

	docs := &bytes.Buffer{}
	docs.WriteString(docsHeader)

	kernels := 0

	if err := filepath.Walk(btfDir, func(path string, info fs.FileInfo, retErr error) error {
		if info.IsDir() || filepath.Ext(path) != ".btf" {
			return nil
		}

		// A path should consist of:
		// - the btf dir
		// - the OS
		// - the OS version
		// - the architecture
		// - the btf file containing the kernel version
		pathSplit := strings.Split(path, string(os.PathSeparator))
		const expectedBPFPathLen = 9
		if len(pathSplit) != expectedBPFPathLen {
			return fmt.Errorf("invalid btf path: %s (len = %d)", path, len(pathSplit))
		}

		btfBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read btf file: %w", err)
		}

		os := types.Os(pathSplit[5])
		osVersion := types.OsVersion(pathSplit[6])
		arch := types.Arch(pathSplit[7])
		kernel := types.Kernel(pathSplit[8][0 : len(pathSplit[8])-len(filepath.Ext(pathSplit[8]))])

		// Kernel versions lower than 5.8 are not supported right now,
		// so we skip them.
		kernelString := strings.ReplaceAll(string(kernel), "_", "-") // underscore is not parsable
		kernelVersion, err := semver.Parse(kernelString)
		if err != nil {
			return fmt.Errorf("parse kernel version %s: %w", kernelString, err)
		}
		// Ignore the pre otherwise the comparison will fail below
		kernelVersion.Pre = nil

		const (
			lowestMajor = 5
			lowestMinor = 8
		)
		if kernelVersion.LT(semver.Version{Major: lowestMajor, Minor: lowestMinor}) {
			return nil
		}

		if _, ok := btfs[os]; !ok {
			btfs[os] = map[types.OsVersion]map[types.Arch]map[types.Kernel][]byte{}
			fmt.Fprintf(docs, "- %s\n", os)
		}
		if _, ok := btfs[os][osVersion]; !ok {
			const indent = 2
			btfs[os][osVersion] = map[types.Arch]map[types.Kernel][]byte{}
			fmt.Fprintf(docs, "%s- %s\n", strings.Repeat(" ", indent), osVersion)
		}
		if _, ok := btfs[os][osVersion][arch]; !ok {
			btfs[os][osVersion][arch] = map[types.Kernel][]byte{}
			fmt.Fprintf(docs, "%s- %s\n", strings.Repeat(" ", 4), arch)
		}

		btfs[os][osVersion][arch][kernel] = btfBytes
		fmt.Fprintf(docs, "%s- %s\n", strings.Repeat(" ", 6), kernel)
		kernels++

		return nil
	}); err != nil {
		return fmt.Errorf("walk btf files: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(btfs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal btf JSON: %w", err)
	}

	builder.Write(jsonBytes)
	builder.WriteString("`\n")

	fmt.Fprintf(docs, "\nSum: %d\n", kernels)

	if err := os.WriteFile(
		docsFile, docs.Bytes(), fs.FileMode(0o644),
	); err != nil {
		return fmt.Errorf("write docs file: %w", err)
	}

	return nil
}
