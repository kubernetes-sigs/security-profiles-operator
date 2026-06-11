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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	ErrContainerIDSearchFailed = errors.New("failed looking for container ID")
)

// ContainerIDForPID tries to find the 64 digit container ID for the provided
// PID by using its cgroup. It supports caching via the cache argument.
func ContainerIDForPID(cache *ttlcache.Cache[string, string], pid int) (string, error) {
	stat, err := getProcessStartTime(pid)
	if err != nil {
		return "", fmt.Errorf("reading proc start time: %w", err)
	}

	// Combine the pid with the process start time as a cache key to avoid "fork-bomb"
	// attack which reuse a PID for a different container within the cache TTL.
	cacheKey := strconv.Itoa(pid) + "_" + stat

	// Check the cache first
	item := cache.Get(cacheKey)
	if item != nil {
		return item.Value(), nil
	}

	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)

	file, err := os.Open(filepath.Clean(cgroupPath))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProcessNotFound, err)
	}

	defer func() {
		cerr := file.Close()
		if err == nil {
			err = cerr
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()

		if containerIDs := ContainerIDRegex.FindAllString(text, -1); 0 < len(containerIDs) {
			// Using the last container ID in the cgroup path to support "docker in docker" use cases
			containerID := containerIDs[len(containerIDs)-1]
			// Update the cache
			cache.Set(cacheKey, containerID, ttlcache.DefaultTTL)

			return containerID, nil
		}
	}
	// Check if not finding a container ID was caused by any scanning errors.
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrContainerIDSearchFailed, err)
	}

	return "", ErrContainerIDNotFound
}

// getProcessStartTime return the start time for a process.
func getProcessStartTime(pid int) (string, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", fmt.Errorf("reading proc start time for %d pid: %w", pid, err)
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 22 {
		return "", fmt.Errorf("invalid proc stat format for pid: %d", pid)
	}
	return fields[21], nil
}
