/*
Copyright 2023 The Kubernetes Authors.

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

package cli

import (
	"fmt"
	"runtime"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// ParsePlatform parses an OCI image spec platform from the provided string.
func ParsePlatform(input string) (*v1.Platform, error) {
	res := &v1.Platform{}

	if input == "" {
		res.Architecture = runtime.GOARCH
		res.OS = runtime.GOOS

		return res, nil
	}

	platformStr, osVersion, _ := strings.Cut(input, ":")
	res.OSVersion = osVersion
	parts := strings.Split(platformStr, "/")

	switch len(parts) {
	case 3:
		res.Variant = parts[2]

		fallthrough
	case 2:
		res.Architecture = parts[1]
	case 1:
		res.Architecture = runtime.GOARCH
	default:
		return nil, fmt.Errorf("unable to parse platform from %s", input)
	}

	res.OS = parts[0]
	if res.OS == "" {
		return nil, fmt.Errorf("unable to parse OS from %s", input)
	}

	if res.Architecture == "" {
		return nil, fmt.Errorf("unable to parse architecture from %s", input)
	}

	return res, nil
}
