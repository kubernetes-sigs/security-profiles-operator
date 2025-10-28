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

// BPFHelperIsSupported checks if a specific BPF helper function is supported for a given program type.
// This function probes the BPF helper using libbpf and returns whether the helper is supported.
//
// Important Notes for the Caller:
//
//  1. libbpf probes may return success (`true`) even if the BPF program load would fail due to permission issues (EPERM).
//     To ensure reliability, it is necessary to either run with sufficient capabilities or explicitly check for EPERM.
//     Reference: https://github.com/libbpf/bpftool/blob/a5c058054cc71836930e232162e8bd1ec6705eaf/src/feature.c#L694-L701
//
//  2. libbpf does not always clear `errno` in certain scenarios. For example, if the file `/proc/version_signature`
//     is missing, libbpf may set `errno` to ENOENT (errno=2) and leave it uncleared, even if the helper is supported.
//     Reference: https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf_probes.c#L33-L39
//
//  3. If the function returns `true` while running with appropriate capabilities, the helper is assumed to be supported.
//     This behavior is documented in libbpf:
//     Reference: https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf_probes.c#L448-L464
//
// Caveats:
//   - A return value of `true` does not guarantee that the BPF program will load successfully. It is critical to verify
//     permissions or run with sufficient capabilities for accurate results.
//   - If `retC < 0`, the helper is not supported. In such cases, additional details can be found in `errno`.
func BPFHelperIsSupported(progType BPFProgType, funcId BPFFunc) (bool, error) {
	retC, errno := C.libbpf_probe_bpf_helper(C.enum_bpf_prog_type(int(progType)), C.enum_bpf_func_id(int(funcId)), nil)

	var innerErr error

	// helper not supported
	if retC < 0 {
		return false, fmt.Errorf("operation failed for function `%s` with program type `%s`: %w. (errno: %v)", funcId, progType, syscall.Errno(-retC), errno)
	}

	// Handle unexpected errno values returned by libbpf. For example, errno may still
	// contain a previous value like ENOENT, even when the helper is supported.
	if errno != nil {
		innerErr = fmt.Errorf("unexpected errno for function `%s` with program type `%s`. (errno: %v)", funcId, progType, errno)
	}

	// If running with capabilities and retC==1 its assumed the helper is supported. Reference:
	// https://github.com/libbpf/libbpf/blob/09b9e83102eb8ab9e540d36b4559c55f3bcdb95d/src/libbpf_probes.c#L448-L464
	return retC == 1, innerErr
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
