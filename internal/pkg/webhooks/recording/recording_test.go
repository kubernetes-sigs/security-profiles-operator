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

package recording

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/recording/recordingfakes"
)

var errTest = errors.New("error")

func TestHandle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*recordingfakes.FakeImpl)
		request admission.Request
		assert  func(admission.Response)
	}{
		{ // success pod unchanged
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(&corev1.Pod{}, nil)
			},
			assert: func(resp admission.Response) {
				require.True(t, resp.Allowed)
				require.Equal(t, http.StatusOK, int(resp.Result.Code))
				require.Equal(t, metav1.StatusReason("pod unchanged"), resp.Result.Reason)
			},
		},
		{ // error could not list profile recordings
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusInternalServerError, int(resp.Result.Code))
			},
		},
		{ // error failed to decode pod
			prepare: func(mock *recordingfakes.FakeImpl) {
				mock.ListProfileRecordingsReturns(&v1alpha1.ProfileRecordingList{}, nil)
				mock.DecodePodReturns(nil, errTest)
			},
			assert: func(resp admission.Response) {
				require.Equal(t, http.StatusBadRequest, int(resp.Result.Code))
			},
		},
	} {
		mock := &recordingfakes.FakeImpl{}
		tc.prepare(mock)

		recorder := podSeccompRecorder{impl: mock, log: logr.Discard()}
		resp := recorder.Handle(context.Background(), admission.Request{})
		tc.assert(resp)
	}
}
