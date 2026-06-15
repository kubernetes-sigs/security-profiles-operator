/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jellydator/ttlcache/v3"
)

var (
	// ContainerIDRegex is the regular expression for determining the 64 digit
	// container ID.
	ContainerIDRegex = regexp.MustCompile(`[0-9a-f]{64}`)

	// ErrProcessNotFound is the error returned by ContainerIDForPID if the
	// process path could not be found in /proc.
	ErrProcessNotFound = errors.New("process not found in cgroup path")

	// ErrContainerIDNotFound is the error returned by ContainerIDForPID if the
	// cgroup does not contain any container ID.
	ErrContainerIDNotFound = errors.New("unable to find container ID in cgroup path")

	// errContainerIDSearchFailed is the error returned with a reason by
	// ContainerIDForPID if it fails to parse the container ID from the logs.
	errContainerIDSearchFailed = errors.New("failed looking for container ID")
)

// procFileReader reads a /proc/<pid>/<file> for a given PID, allowing
// dependency injection in tests.
type procFileReader func(pid int) ([]byte, error)

// ContainerIDForPID tries to find the 64 digit container ID for the provided
// PID by using its cgroup. It supports caching via the cache argument.
func ContainerIDForPID(cache *ttlcache.Cache[string, string], pid int) (string, error) {
	readFile := func(pid int) ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	}
	readCgroup := func(pid int) ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	}

	return containerIDForPID(cache, pid, readFile, readCgroup)
}

func containerIDForPID(
	cache *ttlcache.Cache[string, string],
	pid int,
	statReader, cgroupReader procFileReader,
) (string, error) {
	startTime, err := getProcessStartTimeTicks(pid, statReader)
	if err != nil {
		return "", fmt.Errorf("reading proc start time: %w", err)
	}

	// Combine the pid with the process start time as a cache key to avoid "fork-bomb"
	// attack which reuses a PID for a different container within the cache TTL.
	cacheKey := strconv.Itoa(pid) + "_" + startTime

	item := cache.Get(cacheKey)
	if item != nil {
		return item.Value(), nil
	}

	cgroupData, err := cgroupReader(pid)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(cgroupData))
	for scanner.Scan() {
		text := scanner.Text()

		if containerIDs := ContainerIDRegex.FindAllString(text, -1); 0 < len(containerIDs) {
			// Using the last container ID in the cgroup path to support "docker in docker" use cases
			containerID := containerIDs[len(containerIDs)-1]
			cache.Set(cacheKey, containerID, ttlcache.DefaultTTL)

			return containerID, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", errContainerIDSearchFailed, err)
	}

	return "", ErrContainerIDNotFound
}

// getProcessStartTimeTicks return the start time for a process.
func getProcessStartTimeTicks(pid int, reader procFileReader) (string, error) {
	stat, err := reader(pid)
	if err != nil {
		return "", fmt.Errorf("reading proc start time for %d pid: %w", pid, err)
	}

	// The comm field (field 2) is in parentheses and can contain spaces,
	// so split after the last ")" to get reliable field indices.
	raw := string(stat)

	i := strings.LastIndexByte(raw, ')')
	if i < 0 || i+2 >= len(raw) {
		return "", fmt.Errorf("invalid proc stat format for pid: %d", pid)
	}
	// After ")" the fields are: state(3) ppid(4) ... starttime(22),
	// which is index 19 in the zero-based slice after ")".
	fields := strings.Fields(raw[i+2:])
	if len(fields) < 20 {
		return "", fmt.Errorf("invalid proc stat format for pid: %d", pid)
	}

	return fields[19], nil
}
