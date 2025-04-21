// Package which - locates executable files in the current path. A cross-platform
// implementation of the `which(1)` command.
//
// This allows finding programs by searching the current `PATH` environment
// variable without needing to shell out to the operating system's `which` command.
package which

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Which locates executable program(s) in the user's path. If more than one
// occurrence is found, the first will be returned. Unlike the UNIX which(1)
// command, even if multiple programs are given as input, only the first-found
// will be returned. If none of the programs are found, the empty string is
// returned.
func Which(program ...string) string {
	for _, prog := range program {
		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(candidate) {
				return candidate
			}
		}
	}

	return ""
}

// All returns all instances of the executable program(s), instead of just the
// first one.
func All(program ...string) []string {
	out := []string{}

	for _, prog := range program {
		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(candidate) {
				out = append(out, candidate)
			}
		}
	}

	return out
}

// Found returns true if all of the given executable program(s) are found, false
// if one or more are not found.
func Found(program ...string) bool {
	count := 0
	for _, prog := range program {
		count = 0

		for _, p := range getPath() {
			candidate := filepath.Join(p, prog)
			if isExec(candidate) {
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
	return strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
}

//nolint:gochecknoglobals
var testFS fs.FS

// fsysFor returns the filesystem and the relative path for an absolute path.
// Handles Windows by not assuming all paths are rooted at /
func fsysFor(path string) (fs.FS, string) {
	//nolint:mnd
	parts := strings.SplitAfterN(path, "/", 2)

	root := parts[0]
	if root == "" {
		root = "/"
	}

	if len(parts) > 1 {
		path = parts[1]
	}

	if path == "" {
		path = "."
	}

	if testFS != nil {
		return testFS, path
	}

	return os.DirFS(root), path
}

// isExec returns true when the file at an absolute path is a regular file with
// the execute bit set (if on UNIX)
func isExec(p string) bool {
	fsys, path := fsysFor(filepath.ToSlash(p))

	fi, err := fs.Stat(fsys, path)

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
