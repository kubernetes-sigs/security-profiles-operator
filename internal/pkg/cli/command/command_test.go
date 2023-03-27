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

package command

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command/commandfakes"
)

var errTest = errors.New("test")

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		prepare func(*commandfakes.FakeImpl)
		assert  func(*commandfakes.FakeImpl, error, error)
	}{
		{
			name: "success",
			prepare: func(mock *commandfakes.FakeImpl) {
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on Wait",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.CmdWaitReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.Error(t, waitErr)
			},
		},
		{
			name: "success with error on Signal",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.NotifyCalls(func(c chan<- os.Signal, s ...os.Signal) { c <- s[0] })
				mock.SignalReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.NoError(t, runErr)
				require.NoError(t, waitErr)
			},
		},
		{
			name: "failure on CmdStart",
			prepare: func(mock *commandfakes.FakeImpl) {
				mock.CmdStartReturns(errTest)
			},
			assert: func(mock *commandfakes.FakeImpl, runErr, waitErr error) {
				require.Error(t, runErr)
				require.NoError(t, waitErr)
			},
		},
	} {
		prepare := tc.prepare
		assert := tc.assert

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &commandfakes.FakeImpl{}
			prepare(mock)

			sut := New(Default())
			sut.impl = mock

			_, runErr := sut.Run()
			waitErr := sut.Wait()

			assert(mock, runErr, waitErr)
		})
	}
}
