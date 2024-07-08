/*
Copyright 2020 The Kubernetes Authors.

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

package nonrootenabler_test

import (
	"errors"
	"os"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/nonrootenabler/nonrootenablerfakes"
)

var errTest = errors.New("error")

func TestRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prepare     func(*nonrootenablerfakes.FakeImpl)
		shouldError bool
	}{
		{ // success
			prepare:     func(*nonrootenablerfakes.FakeImpl) {},
			shouldError: false,
		},
		{ // success symlink exists
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.StatReturns(nil, errTest)
			},
			shouldError: false,
		},
		{ // failure on CopyDirContentsLocal
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.CopyDirContentsLocalReturns(errTest)
			},
			shouldError: true,
		},
		{ // failure on Chown
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.ChownReturns(errTest)
			},
			shouldError: true,
		},
		{ // failure on Symlink
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.StatReturns(nil, os.ErrNotExist)
				mock.SymlinkReturns(errTest)
			},
			shouldError: true,
		},
		{ // failure on Chown
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.ChownReturns(errTest)
			},
			shouldError: true,
		},
		{ // failure on MkdirAll with KubeletSeccompRootPath
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MkdirAllReturnsOnCall(0, errTest)
			},
			shouldError: true,
		},
		{ // failure on MkdirAll with OperatorRoot
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.MkdirAllReturnsOnCall(1, errTest)
			},
			shouldError: true,
		},
		{ // failure on SaveKubeletConfig failure
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.SaveKubeletConfigReturns(errTest)
			},
			shouldError: true,
		},
		{ // success on SaveKubeletDir success
			prepare: func(mock *nonrootenablerfakes.FakeImpl) {
				mock.SaveKubeletConfigReturns(nil)
			},
			shouldError: false,
		},
	} {
		sut := nonrootenabler.New()
		mock := &nonrootenablerfakes.FakeImpl{}
		tc.prepare(mock)
		sut.SetImpl(mock)

		err := sut.Run(logr.Discard(), "", config.KubeletDir())
		if tc.shouldError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}
