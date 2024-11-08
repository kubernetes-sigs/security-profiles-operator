package hostop

import (
	"github.com/go-logr/logr"
)

type hostOpOpts struct {
	logger          logr.Logger
	insideContainer func() bool
	hostPidCheck    func() bool
}

type HostOpOption func(*hostOpOpts)

func (h *hostOpOpts) applyOpts(opts ...HostOpOption) {
	for _, o := range opts {
		o(h)
	}
}

// WithLogger sets a logger to be used whilst executing operations.
func WithLogger(logger logr.Logger) HostOpOption {
	return func(o *hostOpOpts) {
		o.logger = logger
	}
}

// WithAssumeContainer ensures that HostOp always assume it is being executed
// from inside a container, and therefore attempts the necessary privilege
// escalations.
func WithAssumeContainer() HostOpOption {
	return func(o *hostOpOpts) {
		o.insideContainer = func() bool { return true }
	}
}

// WithAssumeHost ensures that HostOp always assume that it is being executed
// directly in the host.
func WithAssumeHost() HostOpOption {
	return func(o *hostOpOpts) {
		o.insideContainer = func() bool { return false }
	}
}

// WithAssumeHostPidNamespace ensures that HostOp always assume that the container
// runs into the host PID namespace.
func WithAssumeHostPidNamespace() HostOpOption {
	return func(o *hostOpOpts) {
		o.hostPidCheck = func() bool { return false }
	}
}
