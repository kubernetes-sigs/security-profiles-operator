//go:build !linux || !apparmor
// +build !linux !apparmor

package apparmor

func NewAppArmor() aa {
	return &unsupported{}
}
