//go:build linux
// +build linux

package hostop

import (
	"bufio"
	"os"
	"strings"
)

// containerIdentifierFiles defines files that identifies the
// current context is inside a container.
var containerIdentifierFiles = []string{
	"/.dockerenv",
	"/run/.containerenv",
}

// hostIdentifierExec defines executables that are executed on pid 1
// when running at host's pid namespace.
var hostIdentifierExec = []string{
	"init",
	"systemd",
}

// InsideContainer checks whether the current process is being executed
// inside of a container.
func InsideContainer() bool {
	for _, file := range containerIdentifierFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return checkCgroup()
}

// checkCgroup checks the cgroup file for the crio signature
// this is a temporary fix until support is added upstream.
func checkCgroup() bool {
	f, err := os.Open("/proc/self/cgroup")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "crio-") {
			return true
		}

		if err := scanner.Err(); err != nil {
			break
		}
	}
	return false
}

// HostPidNamespace checks whether the current process is using
// host's PID namespace.
func HostPidNamespace() (bool, error) {
	file, err := os.Open("/proc/1/sched")
	if err != nil {
		return false, err
	}
	defer func() {
		file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	if scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, " ")

		if len(split) > 0 {
			exec := split[0]
			for _, hostExec := range hostIdentifierExec {
				if exec == hostExec {
					return true, nil
				}
			}
		}
	}
	return false, nil
}
