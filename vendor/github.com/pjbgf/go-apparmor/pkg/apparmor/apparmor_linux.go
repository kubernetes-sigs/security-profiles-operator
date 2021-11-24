//go:build linux
// +build linux

package apparmor

// #cgo LDFLAGS: -lapparmor
// #include <fcntl.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/apparmor.h>
import "C"
import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"unsafe"
)

const (
	modulePath string = "/sys/module/apparmor"
)

var (
	findAppArmorParser sync.Once
	appArmorParserPath string
)

// Enforceable checks whether AppArmor is installed, enabled and that
// policies are enforceable.
func (a *AppArmor) Enforceable() bool {
	return aaModuleLoaded()
}

// DeletePolicy removes an AppArmor policy from the kernel.
func (a *AppArmor) DeletePolicy(policyName string) error {
	if ok, err := hasEnoughPrivileges(); !ok {
		return err
	}

	a.logger.V(2).Info(fmt.Sprintf("policy name: %s", policyName))

	var kernel_interface *C.aa_kernel_interface

	cPolicyName := C.CString(policyName)
	defer C.free(unsafe.Pointer(cPolicyName))

	if C.aa_kernel_interface_new(&kernel_interface, nil, nil) != 0 {
		return fmt.Errorf("call aa_kernel_interface_new")
	}

	var err error
	if C.aa_kernel_interface_remove_policy(kernel_interface, cPolicyName) != 0 {
		err = fmt.Errorf("call aa_kernel_interface_remove_policy")
	}
	C.aa_kernel_interface_unref(kernel_interface)

	return err
}

// LoadPolicy loads an AppArmor policy into the kernel.
func (a *AppArmor) LoadPolicy(fileName string) error {
	if ok, err := hasEnoughPrivileges(); !ok {
		return err
	}

	parserPath := appArmorParser()
	if len(parserPath) == 0 {
		return fmt.Errorf("cannot find apparmor_parser")
	}

	a.logger.V(2).Info(fmt.Sprintf("policy file: %s", fileName))
	fileName, err := filepath.Abs(fileName)
	if err != nil {
		return fmt.Errorf("cannot get abs from file")
	}

	fd, err := os.CreateTemp("", "aa_profile_bin_*")
	if err != nil {
		return fmt.Errorf("cannot create tmp file")
	}
	defer func() {
		if err := fd.Close(); err != nil {
			a.logger.V(1).Info(fmt.Sprintf("closing file: %s", err))
		}
	}()

	cmd := exec.Command(parserPath, fileName, "-o", fd.Name())
	a.logger.V(2).Info(fmt.Sprintf("transform policy into binary: %s", cmd.Args))

	err = cmd.Run()
	if err != nil {
		return err
	}

	var kernel_interface *C.aa_kernel_interface

	if C.aa_kernel_interface_new(&kernel_interface, nil, nil) != 0 {
		return fmt.Errorf("aa_kernel_interface_new")
	}

	cFileName := C.CString(fd.Name())
	defer C.free(unsafe.Pointer(cFileName))

	retVal := C.aa_kernel_interface_replace_policy_from_file(kernel_interface, C.AT_FDCWD, cFileName)

	C.aa_kernel_interface_unref(kernel_interface)
	if retVal != 0 {
		err = fmt.Errorf("aa_kernel_interface_replace_policy_from_file")
	}

	return err
}

func appArmorParser() string {
	findAppArmorParser.Do(func() {
		locations := []string{
			"/usr/sbin/apparmor_parser",
			"/sbin/apparmor_parser",
		}

		for _, location := range locations {
			if _, err := os.Stat(location); err == nil {
				appArmorParserPath = location
			}
		}
	})
	return appArmorParserPath
}

func hasEnoughPrivileges() (bool, error) {
	euid := os.Geteuid()
	uid := os.Getuid()

	if uid == 0 && euid == 0 {
		return true, nil
	}

	filename := filepath.Base(os.Args[0])
	errMessage := fmt.Sprintf("%s must run as root", filename)
	if euid == 0 {
		return false, errors.New("setuid is not supported")
	}

	return false, errors.New(errMessage)
}

// moduleLoaded checks whether the AppArmor module is loaded into the kernel.
func aaModuleLoaded() bool {
	_, err := os.Stat(modulePath)
	return err != nil
}
