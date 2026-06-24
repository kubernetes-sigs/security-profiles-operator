/*
Copyright The Kubernetes Authors.

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

// Package merge provides shared utilities for security profile merge operations.
package merge

import (
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
)

// Fold validates and merges a slice of profiles using pairwise reduction.
// A single profile is cloned; two or more are merged left to right.
func Fold[T any](
	profiles []*T,
	clone func(*T) *T,
	merge func(*T, *T) *T,
) (*T, error) {
	if len(profiles) == 0 {
		return nil, ErrNoProfiles
	}

	for idx, profile := range profiles {
		if profile == nil {
			return nil, fmt.Errorf("profile at index %d: %w", idx, ErrNilProfile)
		}
	}

	if len(profiles) == 1 {
		return clone(profiles[0]), nil
	}

	result := merge(profiles[0], profiles[1])

	for idx := 2; idx < len(profiles); idx++ {
		result = merge(result, profiles[idx])
	}

	return result, nil
}

const smallSliceThreshold = 16

// IntersectSlice returns elements present in both left and right.
func IntersectSlice[T comparable](left, right []T) []T {
	switch {
	case len(left) == 0 || len(right) == 0:
		return nil
	case len(left)+len(right) <= smallSliceThreshold:
		return intersectSliceSmall(left, right)
	default:
		return intersectSliceLarge(left, right)
	}
}

func intersectSliceSmall[T comparable](left, right []T) []T {
	result := make([]T, 0, min(len(left), len(right)))

	for _, val := range left {
		if slices.Contains(right, val) && !slices.Contains(result, val) {
			result = append(result, val)
		}
	}

	return result
}

func intersectSliceLarge[T comparable](left, right []T) []T {
	rightSet := make(map[T]struct{}, len(right))
	for _, val := range right {
		rightSet[val] = struct{}{}
	}

	result := make([]T, 0, min(len(left), len(right)))
	seen := make(map[T]struct{}, len(left))

	for _, val := range left {
		if _, ok := rightSet[val]; ok {
			if _, dup := seen[val]; !dup {
				seen[val] = struct{}{}
				result = append(result, val)
			}
		}
	}

	return result
}

// UnionSlice returns all unique elements from left and right, preserving order.
func UnionSlice[T comparable](left, right []T) []T {
	switch {
	case len(left) == 0 && len(right) == 0:
		return nil
	case len(left) == 0:
		return slices.Clone(right)
	case len(right) == 0:
		return slices.Clone(left)
	case len(left)+len(right) <= smallSliceThreshold:
		return unionSliceSmall(left, right)
	default:
		return unionSliceLarge(left, right)
	}
}

func unionSliceSmall[T comparable](left, right []T) []T {
	result := make([]T, 0, len(left)+len(right))

	for _, val := range left {
		if !slices.Contains(result, val) {
			result = append(result, val)
		}
	}

	for _, val := range right {
		if !slices.Contains(result, val) {
			result = append(result, val)
		}
	}

	return result
}

func unionSliceLarge[T comparable](left, right []T) []T {
	result := make([]T, 0, len(left)+len(right))
	seen := make(map[T]struct{})

	for _, val := range left {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	for _, val := range right {
		if _, ok := seen[val]; !ok {
			seen[val] = struct{}{}
			result = append(result, val)
		}
	}

	return result
}
