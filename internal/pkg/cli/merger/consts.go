/*
Copyright 2024 The Kubernetes Authors.

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

package merger

import "sigs.k8s.io/security-profiles-operator/internal/pkg/cli"

// DefaultOutputFile defines the default output location for the merger.
var DefaultOutputFile = cli.DefaultFile

const (
	// FlagOutputFile is the flag for defining the output file location.
	FlagOutputFile string = cli.FlagOutputFile

	FlagCheck string = "check"
)
