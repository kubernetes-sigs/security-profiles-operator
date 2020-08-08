/*
Copyright 2020 The Kubernetes Authors.

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

package seccomp

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"github.com/go-logr/logr"
	perrors "github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

const statusFilePath = "/proc/self/status"

//counterfeiter:generate . verifier
type verifier interface {
	ParseStatusFile(logr.Logger, string) (map[string]string, error)
	Prctl(int, uintptr, uintptr, uintptr, uintptr) error
}

// Seccomp is the main structure of this package.
type Seccomp struct {
	verifier verifier
}

// New returns a new Seccomp instance.
func New() *Seccomp {
	return &Seccomp{verifier: &defaultVerifier{}}
}

// defaultVerifier is the default verifier abstraction.
type defaultVerifier struct{}

// ParseStatusFile is the status file parse implementation for the default
// verifier.
func (d *defaultVerifier) ParseStatusFile(
	l logr.Logger, filePath string,
) (map[string]string, error) {
	return ParseStatusFile(l, filePath)
}

// Prctl is the Prctl implementation for the default verifier.
func (d *defaultVerifier) Prctl(
	option int, arg2, arg3, arg4, arg5 uintptr,
) error {
	return unix.Prctl(option, arg2, arg3, arg4, arg5)
}

// SetVerifier can be used to replace the internal verifier implementation.
func (s *Seccomp) SetVerifier(v verifier) {
	s.verifier = v
}

// IsSupported returns true if the system has been configured to support
// seccomp.
func (s *Seccomp) IsSupported(l logr.Logger) bool {
	l.Info("Checking if node supports seccomp")

	// try to read from status for kernels > 3.8
	status, err := s.verifier.ParseStatusFile(l, statusFilePath)
	if err == nil {
		l.Info("Node supports seccomp by status file")
		_, ok := status["Seccomp"]
		return ok
	}
	l.Info("Unable to parse status file, trying prctl", "err", err)

	// check if Seccomp is supported via CONFIG_SECCOMP
	if err := s.verifier.Prctl(
		unix.PR_GET_SECCOMP, 0, 0, 0, 0,
	); !errors.Is(err, unix.EINVAL) {
		// Make sure the kernel has CONFIG_SECCOMP_FILTER.
		if err := s.verifier.Prctl(
			unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, 0, 0, 0,
		); !errors.Is(err, unix.EINVAL) {
			l.Info("Node supports seccomp")
			return true
		}
	}

	l.Info("Node does not support seccomp")
	return false
}

// ParseStatusFile reads the provided `file` into a map of strings.
func ParseStatusFile(l logr.Logger, file string) (map[string]string, error) {
	l.Info("Parsing status file", "file", file)
	f, err := os.Open(file)
	if err != nil {
		return nil, perrors.Wrapf(err, "open status file %s", file)
	}
	defer f.Close()

	status := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		parts := strings.SplitN(text, ":", 2)

		if len(parts) <= 1 {
			l.Info("Unable to parse status file entry", "entry", text)
			continue
		}

		status[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	if err := scanner.Err(); err != nil {
		return nil, perrors.Wrapf(err, "scan status file %s", file)
	}

	return status, nil
}
