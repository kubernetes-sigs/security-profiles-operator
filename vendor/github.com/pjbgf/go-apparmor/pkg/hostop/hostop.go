// Package hostop contains an interface to represent the execution of
// atomic host operations at a higher privilege.
package hostop

type NsTypeName string

const (
	Mount NsTypeName = "ns/mnt"
)

type HostOp interface {
	// Do executes the action at a privileged context at the host.
	Do(action func() error) error
}
