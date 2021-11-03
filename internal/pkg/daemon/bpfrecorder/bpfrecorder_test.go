// +build linux

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

package bpfrecorder

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/bpfrecorder/bpfrecorderfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*bpfrecorderfakes.FakeImpl)
		assert  func(*bpfrecorderfakes.FakeImpl, error)
	}{
		{ // SetTTL fails
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.SetTTLReturns(errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // Getenv returns nothing
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.GetenvReturns("")
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
		{ // Getenv returns nothing
			prepare: func(mock *bpfrecorderfakes.FakeImpl) {
				mock.InClusterConfigReturns(nil, errTest)
			},
			assert: func(mock *bpfrecorderfakes.FakeImpl, err error) {
				require.NotNil(t, err)
			},
		},
	} {
		mock := &bpfrecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := New(logr.DiscardLogger{})
		sut.impl = mock

		err := sut.Run()
		tc.assert(mock, err)
	}
}
