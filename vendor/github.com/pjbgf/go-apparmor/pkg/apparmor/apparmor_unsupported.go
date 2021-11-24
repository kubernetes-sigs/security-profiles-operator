//go:build !linux
// +build !linux

package apparmor

func Enforceable() bool {
	return false
}

func DeletePolicy(policyName string) error {
	return fmt.Errof("not supported")
}

func LoadPolicy(fileName string) error {
	return fmt.Errof("not supported")
}
