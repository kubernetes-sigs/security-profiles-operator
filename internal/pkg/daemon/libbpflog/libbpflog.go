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

// Package libbpflog routes the messages of libbpf to a logger, which libbpf
// writes to stderr otherwise.
package libbpflog

import (
	"strings"
	"sync"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/go-logr/logr"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var once sync.Once

// Route has libbpf log through logger. libbpf has one logger per process, so
// the logger of the first call stays. Its debug messages are only logged at
// the verbose level.
func Route(logger logr.Logger) {
	once.Do(func() {
		bpf.SetLoggerCbs(bpf.Callbacks{Log: func(level int, msg string) {
			log(logger, level, msg)
		}})
	})
}

func log(logger logr.Logger, level int, msg string) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}

	if level == bpf.LibbpfDebugLevel {
		logger = logger.V(config.VerboseLevel)
	}

	logger.Info(msg, "source", "libbpf")
}
