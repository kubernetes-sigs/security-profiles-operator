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

type Iter[T any] interface {
	Close()
	Next() (T, bool)
	Error() error
}

func All[T any](it Iter[T]) ([]T, error) {
	xs := []T{}
	for {
		x, ok := it.Next()
		if !ok {
			return xs, it.Error()
		}
		xs = append(xs, x)
	}
}

type sliceIter[T any] struct {
	i  int
	xs []T
}

func SliceIter[T any](xs []T) Iter[T] {
	return &sliceIter[T]{
		xs: xs,
	}
}

func (it *sliceIter[T]) Close() {}

func (it *sliceIter[T]) Next() (T, bool) {
	if it.i >= len(it.xs) {
		return *new(T), false
	}
	x := it.xs[it.i]
	it.i++
	return x, true
}

func (it *sliceIter[T]) Error() error {
	return nil
}

// ErrorIter returns an iterator that has no
// items and always returns the given error.
func ErrorIter[T any](err error) Iter[T] {
	return errorIter[T]{err}
}

type errorIter[T any] struct {
	err error
}

func (it errorIter[T]) Close() {}

func (it errorIter[T]) Next() (T, bool) {
	return *new(T), false
}

func (it errorIter[T]) Error() error {
	return it.err
}
