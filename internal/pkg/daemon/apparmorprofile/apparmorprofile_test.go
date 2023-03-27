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

package apparmorprofile

import (
	"context"
	"testing"

	_ "github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	profilebasev1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"

	cases := []struct {
		name       string
		rec        *Reconciler
		req        reconcile.Request
		wantResult reconcile.Result
		wantErr    error
	}{
		{
			name: "ProfileNotFound",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet: util.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, name)),
				},
				log:     log.Log,
				metrics: metrics.New(),
				manager: NewAppArmorProfileManager(log.Log),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "GotProfile",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet:                     util.NewMockGetFn(nil),
					MockUpdate:                  util.NewMockUpdateFn(nil),
					MockSubResourceWriterUpdate: util.NewMockSubResourceWriterUpdateFn(nil),
				},
				log:     log.Log,
				record:  record.NewFakeRecorder(10),
				manager: NewAppArmorProfileManager(log.Log),
				metrics: metrics.New(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "NotEnabled",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet:                     util.NewMockGetFn(nil),
					MockUpdate:                  util.NewMockUpdateFn(nil),
					MockSubResourceWriterUpdate: util.NewMockSubResourceWriterUpdateFn(nil),
				},
				log:     log.Log,
				record:  record.NewFakeRecorder(10),
				manager: &FakeProfileManager{enabled: false},
				metrics: metrics.New(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResult, gotErr := tc.rec.Reconcile(context.Background(), tc.req)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}
			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

type FakeProfileManager struct {
	enabled   bool
	installed bool
	err       error
}

func (f *FakeProfileManager) Enabled() bool {
	return f.enabled
}

func (f *FakeProfileManager) InstallProfile(p profilebasev1alpha1.StatusBaseUser) (bool, error) {
	return f.installed, f.err
}

func (f *FakeProfileManager) RemoveProfile(p profilebasev1alpha1.StatusBaseUser) error {
	return f.err
}
