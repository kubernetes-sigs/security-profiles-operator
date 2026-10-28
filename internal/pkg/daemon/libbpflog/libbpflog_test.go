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

package libbpflog

import (
	"testing"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
)

func TestLog(t *testing.T) {
	t.Parallel()

	var logged []string

	logger := funcr.New(func(_, args string) {
		logged = append(logged, args)
	}, funcr.Options{})

	log(logger, bpf.LibbpfWarnLevel, "libbpf: map 'events': failed to create\n")
	log(logger, bpf.LibbpfInfoLevel, "libbpf: loaded\n")
	log(logger, bpf.LibbpfDebugLevel, "libbpf: sec 'tracepoint': found program\n")
	log(logger, bpf.LibbpfWarnLevel, "\n")

	require.Equal(t, []string{
		`"level"=0 "msg"="libbpf: map 'events': failed to create" "source"="libbpf"`,
		`"level"=0 "msg"="libbpf: loaded" "source"="libbpf"`,
	}, logged)
}
