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
	"context"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/crossplane/crossplane-runtime/pkg/event"
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

	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
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
		"NotAConfigMap": {
			obj:  &corev1.Secret{},
			want: false,
		},
		"IsProfile": {
			obj: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						seccompProfileAnnotation: "true",
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
		"ConfigMapErrGetProfile": {
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
		"ConfigMapGotProfile": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: func(_ context.Context, n types.NamespacedName, o runtime.Object) error {
						switch o.(type) {
						case *corev1.ConfigMap:
							return nil
						default:
							return kerrors.NewNotFound(schema.GroupResource{}, name)
						}
					},
				},
				log:    log.Log,
				record: event.NewNopRecorder(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		"CRDErrGetProfile": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: func(_ context.Context, n types.NamespacedName, o runtime.Object) error {
						switch o.(type) {
						case *corev1.ConfigMap:
							return errOops
						default:
							return kerrors.NewNotFound(schema.GroupResource{}, name)
						}
					},
				},
				log: log.Log,
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    errors.Wrap(errOops, errGetProfile),
		},
		"CRDGotProfile": {
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(nil),
				},
				log:    log.Log,
				record: event.NewNopRecorder(),
				save:   func(_ string, _ []byte) error { return nil },
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
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

// Expected perms on file.
func TestSaveProfileOnDisk(t *testing.T) {
	// TODO: fix root user execution for this test
	if os.Getuid() == 0 {
		t.Skip("Test does not work as root user")
	}
	dir, err := ioutil.TempDir("", config.OperatorName)
	if err != nil {
		t.Error(errors.Wrap(err, "error creating temp file for tests"))
	}
	defer os.RemoveAll(dir)

	cases := map[string]struct {
		setup       func()
		fileName    string
		contents    string
		wantErr     string
		fileCreated bool
	}{
		"CreateDirsAndWriteFile": {
			fileName:    path.Join(dir, "/seccomp/operator/namespace/configmap/filename.json"),
			contents:    "some content",
			fileCreated: true,
		},
		"NoPermissionToWriteFile": {
			setup: func() {
				targetDir := path.Join(dir, "/test/nopermissions")
				require.Nil(t, os.MkdirAll(targetDir, dirPermissionMode))
				require.Nil(t, os.Chmod(targetDir, 0))
			},
			fileName:    path.Join(dir, "/test/nopermissions/filename.json"),
			contents:    "some content",
			fileCreated: false,
			wantErr:     "cannot save profile: open " + dir + "/test/nopermissions/filename.json: permission denied",
		},
		"NoPermissionToWriteDir": {
			setup: func() {
				targetDir := path.Join(dir, "/nopermissions")
				require.Nil(t, os.MkdirAll(targetDir, dirPermissionMode))
				require.Nil(t, os.Chmod(targetDir, 0))
			},
			fileName:    path.Join(dir, "/nopermissions/test/filename.json"),
			contents:    "some content",
			fileCreated: false,
			wantErr:     "cannot create operator directory: mkdir " + dir + "/nopermissions/test: permission denied",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}

			gotErr := saveProfileOnDisk(tc.fileName, []byte(tc.contents))
			file, _ := os.Stat(tc.fileName) // nolint: errcheck
			gotFileCreated := file != nil

			if tc.wantErr == "" {
				require.NoError(t, gotErr)
			} else {
				require.Equal(t, tc.wantErr, gotErr.Error())
			}
			require.Equal(t, tc.fileCreated, gotFileCreated, "was file created?")
		})
	}
}

func TestGetProfilePath(t *testing.T) {
	cases := map[string]struct {
		want        string
		wantErr     string
		profileName string
		config      *corev1.ConfigMap
	}{
		"AppendNamespaceConfigNameAndProfile": {
			want:        path.Join(config.ProfilesRootPath, "config-namespace", "config-name", "file.js"),
			profileName: "file.js",
			config: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "config-name",
					Namespace: "config-namespace",
				},
			},
		},
		"BlockTraversalAtProfileName": {
			want:        path.Join(config.ProfilesRootPath, "ns", "cfg", "file.js"),
			profileName: "../../../../../file.js",
			config: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cfg",
					Namespace: "ns",
				},
			},
		},
		"BlockTraversalAtConfigName": {
			want:        path.Join(config.ProfilesRootPath, "ns", "cfg", "file.js"),
			profileName: "file.js",
			config: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "../../../../../cfg",
					Namespace: "ns",
				},
			},
		},
		"BlockTraversalAtConfigNamespace": {
			want:        path.Join(config.ProfilesRootPath, "ns", "cfg", "file.js"),
			profileName: "file.js",
			config: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cfg",
					Namespace: "../../../../../ns",
				},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, gotErr := GetProfilePath(tc.profileName, tc.config.ObjectMeta.Namespace, tc.config.ObjectMeta.Name)
			if tc.wantErr == "" {
				require.NoError(t, gotErr)
			} else {
				require.Equal(t, tc.wantErr, gotErr.Error())
			}
			require.Equal(t, tc.want, got)
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

func TestValidateProfile(t *testing.T) {
	for _, tc := range []struct {
		profile       string
		shouldSucceed bool
	}{
		{"wrong", false},
		{`{"defaultAction": true}`, false},
		{`{"syscalls": "wrong"}`, false},
		{`{}`, true},
		{`{"defaultAction": "SCMP_ACT_ALLOW"}`, true},
		{`{"syscalls": []}`, true},
	} {
		msg := "Profile content: " + tc.profile
		err := validateProfile(tc.profile)
		if tc.shouldSucceed {
			require.Nil(t, err, msg)
		} else {
			require.NotNil(t, err, msg)
		}
	}
}
