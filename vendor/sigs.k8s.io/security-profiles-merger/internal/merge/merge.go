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
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	// ErrNoProfiles is returned when no profiles are provided.
	ErrNoProfiles = errors.New("at least one profile is required")
	// ErrNilProfile is returned when a nil profile is provided.
	ErrNilProfile = errors.New("profile must not be nil")
	// ErrEmptyPath is returned when a path rule contains an empty string.
	ErrEmptyPath = errors.New("empty path")
)

// Fold validates and merges a slice of profiles using pairwise reduction.
// A single profile is cloned; two or more are merged left to right.
func Fold[T any](
	profiles []*T,
	clone func(*T) *T,
	mergeFn func(*T, *T) (*T, error),
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

	result, err := mergeFn(profiles[0], profiles[1])
	if err != nil {
		return nil, err
	}

	for idx := 2; idx < len(profiles); idx++ {
		result, err = mergeFn(result, profiles[idx])
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// FormatDiffItems formats added and removed items as a prefixed diff string.
func FormatDiffItems[T ~string](prefix string, removed, added []T) string {
	items := make([]string, 0, len(removed)+len(added))

	for _, r := range removed {
		items = append(items, "-"+string(r))
	}

	for _, a := range added {
		items = append(items, "+"+string(a))
	}

	return prefix + ":" + strings.Join(items, ",")
}

// DiffSlice returns elements added to and removed from left relative to right.
// Both slices are treated as sets; duplicates within a slice are ignored.
// Results are sorted. Returns nil, nil when the sets are equal.
func DiffSlice[T cmp.Ordered](left, right []T) ([]T, []T) {
	if len(left) == 0 && len(right) == 0 {
		return nil, nil
	}

	leftSet := make(map[T]struct{}, len(left))
	for _, item := range left {
		leftSet[item] = struct{}{}
	}

	rightSet := make(map[T]struct{}, len(right))
	for _, item := range right {
		rightSet[item] = struct{}{}
	}

	var added, removed []T

	for item := range leftSet {
		if _, ok := rightSet[item]; !ok {
			removed = append(removed, item)
		}
	}

	for item := range rightSet {
		if _, ok := leftSet[item]; !ok {
			added = append(added, item)
		}
	}

	slices.Sort(added)
	slices.Sort(removed)

	return added, removed
}

// SliceDiff represents added and removed items in a set-like slice.
type SliceDiff[T comparable] struct {
	Added   []T `json:"added,omitempty"`
	Removed []T `json:"removed,omitempty"`
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
	seen := make(map[T]struct{}, len(left)+len(right))

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

// ClonePtr returns a shallow copy of the pointed-to value, or nil if ptr is nil.
func ClonePtr[T any](ptr *T) *T {
	if ptr == nil {
		return nil
	}

	val := *ptr

	return &val
}

// DeduplicateSlice returns a new slice with duplicate elements removed,
// preserving the order of first occurrence.
func DeduplicateSlice[T comparable](items []T) []T {
	if len(items) == 0 {
		return items
	}

	seen := make(map[T]struct{}, len(items))
	result := make([]T, 0, len(items))

	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}
