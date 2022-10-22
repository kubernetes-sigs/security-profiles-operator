package apparmor

import (
	"github.com/go-logr/logr"
)

type appArmorOpts struct {
	logger    logr.Logger
	policyDir string
}

type AppArmorOption func(*appArmorOpts)

func (a *appArmorOpts) applyOpts(opts ...AppArmorOption) {
	for _, o := range opts {
		o(a)
	}
}

// WithLogger sets a logger to be used whilst executing operations.
func WithLogger(logger logr.Logger) AppArmorOption {
	return func(o *appArmorOpts) {
		o.logger = logger
	}
}
