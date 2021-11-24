// Package hostop contains an interface to represent the execution of
// atomic host operations at a higher privilege.
package hostop

import logr "github.com/go-logr/logr"

type NsTypeName string

const (
	Mount NsTypeName = "ns/mnt"
)

type HostOp interface {
	// Do executes the action at a privileged context at the host.
	Do(action func() error) error

	// WithLogger sets the logger to be used for logging.
	WithLogger(logr.Logger) HostOp
}
