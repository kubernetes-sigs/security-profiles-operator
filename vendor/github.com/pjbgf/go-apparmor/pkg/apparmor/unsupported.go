package apparmor

import (
	"errors"

	"github.com/go-logr/logr"
)

var (
	aaNotSupported = errors.New("appArmor is not supported by the underlying OS")
)

type unsupported struct {
}

func (a unsupported) WithLogger(l logr.Logger) aa {
	return a
}

func (unsupported) Enabled() (bool, error) {
	return false, aaNotSupported
}

func (unsupported) Enforceable() (bool, error) {
	return false, aaNotSupported
}

func (unsupported) AppArmorFS() (string, error) {
	return "", aaNotSupported
}

func (unsupported) DeletePolicy(policyName string) error {
	return aaNotSupported
}

func (unsupported) LoadPolicy(fileName string) error {
	return aaNotSupported
}
