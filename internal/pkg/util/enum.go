/*
Copyright 2025 The Kubernetes Authors.

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
	"flag"
	"fmt"
	"strings"
)

type EnumValue struct {
	Enum     []string
	Default  string
	selected string
}

var _ flag.Value = (*EnumValue)(nil)

// NewEnumValue returns a new EnumValue. Returns nil if defaultValue is not found in enum.
func NewEnumValue(enum []string, defaultValue string) *EnumValue {
	for _, v := range enum {
		if v == defaultValue {
			return &EnumValue{Enum: enum, Default: defaultValue}
		}
	}

	return nil
}

// Set method is used by cli.GenericFlag. But the IDE won't recognize it.
func (e *EnumValue) Set(value string) error {
	for _, enum := range e.Enum {
		if strings.EqualFold(enum, value) {
			e.selected = enum

			return nil
		}
	}

	return fmt.Errorf("allowed values are %s", strings.Join(e.Enum, ", "))
}

func (e *EnumValue) String() string {
	if e.selected == "" {
		return e.Default
	}

	return e.selected
}
