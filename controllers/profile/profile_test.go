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

package profile

import (
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestIsProfile(t *testing.T) {
	cases := map[string]struct {
		obj  runtime.Object
		want bool
	}{
		"NotAProfile": {
			obj:  &corev1.ConfigMap{},
			want: false,
		},
		"IsProfile": {
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						SeccompProfileAnnotation: "true",
					},
				},
			},
			want: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := isProfile(tc.obj)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestReconcile(t *testing.T) {
	name := "cool-profile"
	namespace := "cool-namespace"

	errOops := errors.New("oops")

	cases := map[string]struct {
		rec        *Reconciler
		req        reconcile.Request
		wantResult reconcile.Result
		wantErr    error
	}{
		"ProfileNotFound": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, name)),
				},
				log: log.Log,
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		"ErrGetProfile": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(errOops),
				},
				log: log.Log,
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    errors.Wrap(errOops, errGetProfile),
		},
		"GotProfile": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(nil, func(obj runtime.Object) error {
						return nil
					}),
				},
				log: log.Log,
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{RequeueAfter: longWait},
			wantErr:    nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gotResult, gotErr := tc.rec.Reconcile(tc.req)
			if tc.wantErr != nil {
				require.EqualError(t, gotErr, tc.wantErr.Error())
			}
			require.Equal(t, tc.wantResult, gotResult)
		})
	}
}

func TestIgnoreNotFound(t *testing.T) {
	name := "cool-profile"

	errOops := errors.New("oops")

	cases := map[string]struct {
		err  error
		want error
	}{
		"IsErrorNotFound": {
			err:  kerrors.NewNotFound(schema.GroupResource{}, name),
			want: nil,
		},
		"OtherError": {
			err:  errOops,
			want: errOops,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := ignoreNotFound(tc.err)
			require.Equal(t, tc.want, got)
		})
	}
}
