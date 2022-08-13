//go:build !linux
// +build !linux

package hostop

import (
	logr "github.com/go-logr/logr"
)

type mountHostOp struct {
}

func NewMountHostOp() HostOp {
	return &mountHostOp{}
}

func (m *mountHostOp) WithLogger(logger logr.Logger) HostOp {
	return m
}

func (m *mountHostOp) Do(action func() error) error {
	return nil
}
