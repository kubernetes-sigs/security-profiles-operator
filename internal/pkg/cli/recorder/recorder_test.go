//go:build linux && !no_bpf
// +build linux,!no_bpf

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

package recorder

import (
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder/recorderfakes"
)

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*recorderfakes.FakeImpl) *Options
		assert  func(*recorderfakes.FakeImpl, error)
	}{
		{ // Success
			prepare: func(mock *recorderfakes.FakeImpl) *Options {
				mock.CmdPidReturns(1)
				mock.IteratorNextReturnsOnCall(0, true)
				mock.IteratorKeyReturnsOnCall(0, []byte{1, 0, 0, 0})
				mock.SyscallsGetValueReturns([]byte{1}, nil)
				return Default()
			},
			assert: func(mock *recorderfakes.FakeImpl, err error) {
				require.Nil(t, err)
				require.Equal(t, 1, mock.PrintObjCallCount())
			},
		},
	} {
		mock := &recorderfakes.FakeImpl{}
		options := tc.prepare(mock)

		sut := New(options)
		sut.impl = mock

		err := sut.Run()
		tc.assert(mock, err)
	}
}
