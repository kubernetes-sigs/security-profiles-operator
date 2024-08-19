// Package which - locates executable files in the current path. A cross-platform
// implementation of the `which(1)` command.
//
// This allows finding programs by searching the current `PATH` environment
// variable without needing to shell out to the operating system's `which` command.
package which

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/afero"
)

// Which locates executable program(s) in the user's path. If more than one
// occurrence is found, the first will be returned. Unlike the UNIX which(1)
// command, even if multiple programs are given as input, only the first-found
// will be returned. If none of the programs are found, the empty string is
// returned.
func Which(program ...string) string {
	return which(afero.NewOsFs(), program...)
}

func which(fs afero.Fs, program ...string) string {
	for _, prog := range program {
		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(fs, candidate) {
				return candidate
			}
		}
	}

	return ""
}

// All returns all instances of the executable program(s), instead of just the
// first one.
func All(program ...string) []string {
	return all(afero.NewOsFs(), program...)
}

func all(fs afero.Fs, program ...string) []string {
	out := []string{}

	for _, prog := range program {
		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(fs, candidate) {
				out = append(out, candidate)
			}
		}
	}

	return out
}

// Found returns true if all of the given executable program(s) are found, false
// if one or more are not found.
func Found(program ...string) bool {
	return found(afero.NewOsFs(), program...)
}

func found(fs afero.Fs, program ...string) bool {
	count := 0
	for _, prog := range program {
		count = 0

		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(fs, candidate) {
				count++
			}
		}

		if count == 0 {
			return false
		}
	}

	return count > 0
}

func getPath() []string {
	pathVar := os.Getenv("PATH")
	if pathVar == "" && runtime.GOOS == "windows" {
		for i, k := range keys(os.Environ()) {
			if strings.ToLower(k) == "path" {
				pathVar = os.Environ()[i]
				break
			}
		}
	}

	return strings.Split(pathVar, string(os.PathListSeparator))
}

func keys(env []string) []string {
	out := make([]string, len(env))

	for i, v := range env {
		parts := strings.SplitN(v, "=", 2)
		out[i] = parts[0]
	}

	return out
}

// isExec returns true when the file at the given path is a regular file with
// the execute bit set (if on UNIX)
func isExec(fs afero.Fs, path string) bool {
	fi, err := fs.Stat(path)

	switch {
	case err != nil:
		return false
	case fi.IsDir():
		return false
	case fi.Mode()&0o111 != 0:
		return true
	}
	// Windows filesystems have no execute bit...
	return runtime.GOOS == "windows"
}
