// Copyright 2023 CUE Labs AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ociregistry

// TODO(go1.23) when we can depend on Go 1.23, this should be:
// type Seq[T any] = iter.Seq2[T, error]

// Seq defines the type of an iterator sequence returned from
// the iterator functions. In general, a non-nil
// error means that the item is the last in the sequence.
type Seq[T any] func(yield func(T, error) bool)

func All[T any](it Seq[T]) (_ []T, _err error) {
	xs := []T{}
	// TODO(go1.23) for x, err := range it
	it(func(x T, err error) bool {
		if err != nil {
			_err = err
			return false
		}
		xs = append(xs, x)
		return true
	})
	return xs, _err
}

type sliceIter[T any] struct {
	i  int
	xs []T
}

func SliceIter[T any](xs []T) Seq[T] {
	return func(yield func(T, error) bool) {
		for _, x := range xs {
			if !yield(x, nil) {
				return
			}
		}
	}
}

// ErrorIter returns an iterator that has no
// items and always returns the given error.
func ErrorIter[T any](err error) Seq[T] {
	return func(yield func(T, error) bool) {
		yield(*new(T), err)
	}
}
