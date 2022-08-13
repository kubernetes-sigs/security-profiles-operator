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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/go-logr/logr"
)

const (
	modulePath string = "/sys/module/apparmor"
)

var (
	findAppArmorParser sync.Once
	appArmorParserPath string

	aaExtensionsNotAvailableErr  = errors.New("appArmor extensions to the system are not available")
	aaDisabledAtBootErr          = errors.New("appArmor is available on the system but has been disabled at boot")
	aaInterfaceUnavailableErr    = errors.New("appArmor is available but the interface is not available")
	aaInsufficientMemoryErr      = errors.New("insufficient memory was available")
	aaPermissionDeniedErr        = errors.New("missing sufficient permissions to determine if AppArmor is enabled")
	aaCannotCompleteOperationErr = errors.New("could not complete operation")
	aaAccessToPathDeniedErr      = errors.New("access to the required paths was denied")
	aaFSNotFoundErr              = errors.New("appArmor filesystem mount could not be found")
)

var goOS = func() string {
	return runtime.GOOS
}

// NewAppArmor creates a new instance of the apparmor API.
func NewAppArmor() aa {
	if goOS() == "linux" {
		return &AppArmor{
			logger: logr.Discard(),
		}
	}

	return &unsupported{}
}

type AppArmor struct {
	logger logr.Logger
}

func (a *AppArmor) WithLogger(logger logr.Logger) aa {
	a.logger = logger
	return a
}

func (a *AppArmor) Enabled() (bool, error) {
	e := C.aa_is_enabled()
	if e == 0 {
		return true, nil
	}

	switch syscall.Errno(e) {
	case syscall.ENOSYS:
		return false, aaExtensionsNotAvailableErr
	case syscall.ECANCELED:
		return false, aaDisabledAtBootErr
	case syscall.ENOENT:
		return false, aaInterfaceUnavailableErr
	case syscall.ENOMEM:
		return false, aaInsufficientMemoryErr
	case syscall.EPERM:
		return false, aaPermissionDeniedErr
	case syscall.EACCES:
		return false, aaPermissionDeniedErr
	default:
		return false, fmt.Errorf("checking appArmor status: %w", aaCannotCompleteOperationErr)
	}
}

func (a *AppArmor) Enforceable() (bool, error) {
	enabled, err := a.Enabled()
	if err != nil {
		return false, err
	}

	return enabled && aaParserInstalled(), nil
}

func (a *AppArmor) AppArmorFS() (string, error) {
	aaFS := C.CString("")
	defer C.free(unsafe.Pointer(aaFS))

	e := C.aa_find_mountpoint(&aaFS)
	if e == 0 {
		return C.GoString(aaFS), nil
	}

	switch syscall.Errno(e) {
	case syscall.ENOENT:
		return C.GoString(aaFS), aaFSNotFoundErr
	case syscall.ENOMEM:
		return C.GoString(aaFS), aaInsufficientMemoryErr
	case syscall.EACCES:
		return C.GoString(aaFS), aaAccessToPathDeniedErr
	default:
		return C.GoString(aaFS), fmt.Errorf("appArmor mount point: %w", aaCannotCompleteOperationErr)
	}
}

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

// aaParserInstalled checks whether apparmor_parser is installed.
// this is required to convert plain-text policies into binary,
// which is what aa_kernel_interface_replace_policy_from_file
// expects.
func aaParserInstalled() bool {
	return appArmorParser() != ""
}
