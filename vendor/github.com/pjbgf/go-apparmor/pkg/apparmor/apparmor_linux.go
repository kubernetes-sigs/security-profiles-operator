//go:build linux && apparmor
// +build linux,apparmor

package apparmor

// #cgo LDFLAGS: -lapparmor
// #include <fcntl.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <sys/apparmor.h>
import "C"
import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/go-logr/logr"
)

const (
	defaultPoliciesDir = "/etc/apparmor.d"

	modulePath string = "/sys/module/apparmor"
	// enabledFile is the path to the file that indicates whether apparmor is enabled.
	enabledFile string = "/sys/module/apparmor/parameters/enabled"

	// profilesPath stores the path to the file which contains all loaded profiles.
	profilesPath string = "/sys/kernel/security/apparmor/profiles"
)

var (
	findAppArmorParser sync.Once
	appArmorParserPath string
)

var goOS = func() string {
	return runtime.GOOS
}

// NewAppArmor creates a new instance of the apparmor API.
func NewAppArmor(opts ...AppArmorOption) aa {
	if goOS() == "linux" {
		o := &appArmorOpts{
			logger: logr.Discard(),
		}
		o.applyOpts(opts...)

		return &AppArmor{opts: o}
	}

	return &unsupported{}
}

type AppArmor struct {
	opts *appArmorOpts
}

func (a *AppArmor) Enabled() (bool, error) {
	f, err := os.ReadFile(enabledFile)
	if err != nil {
		return false, fmt.Errorf("cannot read file %s: %w", enabledFile, err)
	}
	if strings.Contains(string(f), "Y") {
		return true, nil
	}

	return false, nil
}

func (a *AppArmor) Enforceable() (bool, error) {
	enabled, err := a.Enabled()
	if err != nil {
		return false, err
	}

	return enabled && aaParserInstalled(), nil
}

func (a *AppArmor) DeletePolicy(policyName string) error {
	a.opts.logger.V(2).Info(fmt.Sprintf("policy name: %s", policyName))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

func (a *AppArmor) LoadPolicy(fileName string) error {
	parserPath := appArmorParser()
	if len(parserPath) == 0 {
		return fmt.Errorf("cannot find apparmor_parser")
	}

	a.opts.logger.V(2).Info(fmt.Sprintf("policy file: %s", fileName))
	fileName, err := filepath.Abs(fileName)
	if err != nil {
		return fmt.Errorf("cannot get abs from file")
	}

	fd, err := os.CreateTemp("", "aa_profile_bin_*")
	if err != nil {
		return fmt.Errorf("cannot create tmp file")
	}
	defer os.Remove(fd.Name())

	cmd := exec.Command(parserPath, fileName, "-o", fd.Name())
	a.opts.logger.V(2).Info(fmt.Sprintf("transform policy into binary: %s", cmd.Args))

	err = cmd.Run()
	if err != nil {
		return err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

func (a *AppArmor) PolicyLoaded(policyName string) (bool, error) {
	readFile, err := os.Open(profilesPath)
	if err != nil {
		return false, fmt.Errorf("cannot open file %s: %w", profilesPath, err)
	}

	s := bufio.NewScanner(readFile)
	for s.Scan() {
		// profiles will be in the format "profile-name (mode: complain/enforce)":
		// sample-profile (enforce)
		if strings.HasPrefix(s.Text(), policyName+" (") {
			return true, nil
		}
	}

	return false, nil
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

// aaParserInstalled checks whether apparmor_parser is installed.
// this is required to convert plain-text policies into binary,
// which is what aa_kernel_interface_replace_policy_from_file
// expects.
func aaParserInstalled() bool {
	return appArmorParser() != ""
}
