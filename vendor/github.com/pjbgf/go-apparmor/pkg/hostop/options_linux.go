//go:build linux
// +build linux

package hostop

// WithContainerDetection ensures that HostOp tries to auto detect whether or
// not the code is being executed from inside a container.
func WithContainerDetection() HostOpOption {
	return func(o *hostOpOpts) {
		o.insideContainer = InsideContainer
	}
}
