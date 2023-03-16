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

package pusher

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/pusher/pusherfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		prepare func(mock *pusherfakes.FakeImpl)
		assert  func(error)
	}{
		{
			name:    "success",
			prepare: func(mock *pusherfakes.FakeImpl) {},
			assert: func(err error) {
				require.NoError(t, err)
			},
		},
		{
			name: "failure on Push",
			prepare: func(mock *pusherfakes.FakeImpl) {
				mock.PushReturns(errTest)
			},
			assert: func(err error) {
				require.ErrorIs(t, err, errTest)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &pusherfakes.FakeImpl{}
			prepare(mock)

			sut := New(Default())
			sut.impl = mock

			err := sut.Run()
			assert(err)
		})
	}
}
