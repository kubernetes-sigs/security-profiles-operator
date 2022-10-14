//go:build !linux || !apparmor
// +build !linux !apparmor

package apparmor

func NewAppArmor(opts ...AppArmorOption) aa {
	return &unsupported{}
}
