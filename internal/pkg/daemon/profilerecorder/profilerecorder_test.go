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

package profilerecorder

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/profilerecorder/profilerecorderfakes"
)

var errTest = errors.New("error")

func TestName(t *testing.T) {
	t.Parallel()
	sut := NewController()
	assert.Equal(t, sut.Name(), "recorder-spod")
}

func TestSchemeBuilder(t *testing.T) {
	t.Parallel()
	sut := NewController()
	assert.Equal(t, sut.SchemeBuilder(), profilerecording1alpha1.SchemeBuilder)
}

func TestSetup(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		prepare func(*profilerecorderfakes.FakeImpl)
		assert  func(error)
	}{
		{ // Success
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.ClientGetCalls(func(
					c client.Client, key types.NamespacedName, obj client.Object,
				) error {
					node, ok := obj.(*corev1.Node)
					assert.True(t, ok)
					node.Status = corev1.NodeStatus{
						Addresses: []corev1.NodeAddress{
							{Type: corev1.NodeInternalIP, Address: "127.0.0.1"},
						},
					}
					return nil
				})
			},
			assert: func(err error) {
				assert.Nil(t, err)
			},
		},
		{ // NewClient fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewClientReturns(nil, errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // ClientGet fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.ClientGetReturns(errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // no node addresses
			prepare: func(mock *profilerecorderfakes.FakeImpl) {},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
		{ // NewControllerManagedBy fails
			prepare: func(mock *profilerecorderfakes.FakeImpl) {
				mock.NewControllerManagedByReturns(errTest)
			},
			assert: func(err error) {
				assert.NotNil(t, err)
			},
		},
	} {
		mock := &profilerecorderfakes.FakeImpl{}
		tc.prepare(mock)

		sut := &RecorderReconciler{impl: mock}

		err := sut.Setup(context.Background(), nil, nil)
		tc.assert(err)
	}
}
