package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"syscall"
)

//
// Version
//

// MajorVersion returns the major semver version of libbpf.
func MajorVersion() int {
	return C.LIBBPF_MAJOR_VERSION
}

// MinorVersion returns the minor semver version of libbpf.
func MinorVersion() int {
	return C.LIBBPF_MINOR_VERSION
}

// LibbpfVersionString returns the string representation of the libbpf version which
// libbpfgo is linked against
func LibbpfVersionString() string {
	return fmt.Sprintf("v%d.%d", MajorVersion(), MinorVersion())
}

//
// Strict Mode
//

// LibbpfStrictMode is an enum as defined in https://github.com/libbpf/libbpf/blob/2cd2d03f63242c048a896179398c68d2dbefe3d6/src/libbpf_legacy.h#L23
type LibbpfStrictMode uint32

const (
	LibbpfStrictModeAll               LibbpfStrictMode = C.LIBBPF_STRICT_ALL
	LibbpfStrictModeNone              LibbpfStrictMode = C.LIBBPF_STRICT_NONE
	LibbpfStrictModeCleanPtrs         LibbpfStrictMode = C.LIBBPF_STRICT_CLEAN_PTRS
	LibbpfStrictModeDirectErrs        LibbpfStrictMode = C.LIBBPF_STRICT_DIRECT_ERRS
	LibbpfStrictModeSecName           LibbpfStrictMode = C.LIBBPF_STRICT_SEC_NAME
	LibbpfStrictModeNoObjectList      LibbpfStrictMode = C.LIBBPF_STRICT_NO_OBJECT_LIST
	LibbpfStrictModeAutoRlimitMemlock LibbpfStrictMode = C.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK
	LibbpfStrictModeMapDefinitions    LibbpfStrictMode = C.LIBBPF_STRICT_MAP_DEFINITIONS
)

func (b LibbpfStrictMode) String() (str string) {
	x := map[LibbpfStrictMode]string{
		LibbpfStrictModeAll:               "LIBBPF_STRICT_ALL",
		LibbpfStrictModeNone:              "LIBBPF_STRICT_NONE",
		LibbpfStrictModeCleanPtrs:         "LIBBPF_STRICT_CLEAN_PTRS",
		LibbpfStrictModeDirectErrs:        "LIBBPF_STRICT_DIRECT_ERRS",
		LibbpfStrictModeSecName:           "LIBBPF_STRICT_SEC_NAME",
		LibbpfStrictModeNoObjectList:      "LIBBPF_STRICT_NO_OBJECT_LIST",
		LibbpfStrictModeAutoRlimitMemlock: "LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK",
		LibbpfStrictModeMapDefinitions:    "LIBBPF_STRICT_MAP_DEFINITIONS",
	}

	str, ok := x[b]
	if !ok {
		str = LibbpfStrictModeNone.String()
	}

	return str
}

// SetStrictMode is no-op as of libbpf v1.0
func SetStrictMode(mode LibbpfStrictMode) {
	C.libbpf_set_strict_mode(uint32(mode))
}

//
// Support
//

func BPFProgramTypeIsSupported(progType BPFProgType) (bool, error) {
	supportedC := C.libbpf_probe_bpf_prog_type(C.enum_bpf_prog_type(int(progType)), nil)
	if supportedC < 1 {
		return false, syscall.Errno(-supportedC)
	}

	return supportedC == 1, nil
}

func BPFMapTypeIsSupported(mapType MapType) (bool, error) {
	supportedC := C.libbpf_probe_bpf_map_type(C.enum_bpf_map_type(int(mapType)), nil)
	if supportedC < 1 {
		return false, syscall.Errno(-supportedC)
	}

	return supportedC == 1, nil
}

// BPFHelperIsSupported checks if a BPF helper function is supported for a given program type.
// Specific capabilities are required depending on the program type to probe the bpf helper function.
func BPFHelperIsSupported(progType BPFProgType, funcId BPFFunc) (bool, error) {
	retC, errno := C.libbpf_probe_bpf_helper(C.enum_bpf_prog_type(int(progType)), C.enum_bpf_func_id(int(funcId)), nil)

	if errno != nil {
		return false, fmt.Errorf("operation failed for function `%s` with program type `%s`: %w", funcId, progType, errno)
	}

	// helper not supported
	if retC < 0 {
		return false, fmt.Errorf("operation failed for function `%s` with program type `%s`: %w", funcId, progType, syscall.Errno(-retC))
	}

	return retC == 1, nil
}

//
// Misc
//

func NumPossibleCPUs() (int, error) {
	nCPUsC := C.libbpf_num_possible_cpus()
	if nCPUsC < 0 {
		return 0, fmt.Errorf("failed to retrieve the number of CPUs: %w", syscall.Errno(-nCPUsC))
	}

	return int(nCPUsC), nil
}
