package apparmor

import (
	"errors"
)

var aaNotSupported = errors.New("appArmor is not enabled or not supported by the underlying OS")

type unsupported struct {
}

func (unsupported) Enabled() (bool, error) {
	return false, aaNotSupported
}

func (unsupported) Enforceable() (bool, error) {
	return false, aaNotSupported
}

func (unsupported) DeletePolicy(policyName string) error {
	return aaNotSupported
}

func (unsupported) LoadPolicy(fileName string) error {
	return aaNotSupported
}

func (unsupported) PolicyLoaded(policyName string) (bool, error) {
	return false, aaNotSupported
}
