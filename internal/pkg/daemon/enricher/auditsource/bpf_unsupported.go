//go:build !(linux && !no_bpf && (amd64 || arm64))

package auditsource

import (
	"errors"

	"github.com/go-logr/logr"
)

func NewBpfSource(logger logr.Logger) (AuditLineSource, error) {
	return nil, errors.New("BPF-based log enricher is unavailable on this platform")
}
