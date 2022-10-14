//go:build !linux
// +build !linux

package hostop

import (
	"errors"
)

var Unsupported = errors.New("hostop is not supported")

type mountHostOp struct {
}

func NewMountHostOp(opts ...HostOpOption) HostOp {
	return &mountHostOp{}
}

func (m *mountHostOp) Do(action func() error) error {
	return Unsupported
}
