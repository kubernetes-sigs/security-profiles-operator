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

package seccompprofile

import (
	"context"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"

	errOops := errors.New("oops")

	// return error only if seccomp is enabled
	getErrorIfSeccompEnabled := func(e error) error {
		if seccomp.IsEnabled() {
			return e
		}
		return nil
	}

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
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(kerrors.NewNotFound(schema.GroupResource{}, name)),
				},
				log:     log.Log,
				metrics: metrics.New(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "ErrGetProfileIfSeccompEnabled",
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet: test.NewMockGetFn(errOops),
				},
				record:  event.NewNopRecorder(),
				log:     log.Log,
				metrics: metrics.New(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    errors.Wrap(getErrorIfSeccompEnabled(errOops), errGetProfile),
		},
		{
			name: "GotProfile",
			rec: &Reconciler{
				client: &test.MockClient{
					MockGet:          test.NewMockGetFn(nil),
					MockUpdate:       test.NewMockUpdateFn(nil),
					MockStatusUpdate: test.NewMockStatusUpdateFn(nil),
				},
				log:     log.Log,
				record:  event.NewNopRecorder(),
				save:    func(_ string, _ []byte) (bool, error) { return false, nil },
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

// Expected perms on file.
func TestSaveProfileOnDisk(t *testing.T) {
	t.Parallel()

	// TODO: fix root user execution for this test
	if os.Getuid() == 0 {
		t.Skip("Test does not work as root user")
	}
	dir, err := ioutil.TempDir("", config.OperatorName)
	if err != nil {
		t.Error(errors.Wrap(err, "error creating temp file for tests"))
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	cases := []struct {
		name        string
		setup       func()
		fileName    string
		contents    string
		wantErr     string
		fileCreated bool
	}{
		{
			name:        "CreateDirsAndWriteFile",
			fileName:    path.Join(dir, "/seccomp/operator/namespace/filename.json"),
			contents:    "some content",
			fileCreated: true,
		},
		{
			name: "NoPermissionToWriteFile",
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
		{
			name: "NoPermissionToWriteDir",
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

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.setup != nil {
				tc.setup()
			}

			_, gotErr := saveProfileOnDisk(tc.fileName, []byte(tc.contents))
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
	t.Parallel()

	cases := []struct {
		name string
		want string
		sp   *v1alpha1.SeccompProfile
	}{
		{
			name: "AppendNamespaceAndProfile",
			want: path.Join(config.ProfilesRootPath, "config-namespace", "file.json"),
			sp: &v1alpha1.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "config-namespace",
				},
			},
		},
		{
			name: "BlockTraversalAtProfileName",
			want: path.Join(config.ProfilesRootPath, "ns", "file.json"),
			sp: &v1alpha1.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "../../../../../file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtTargetName",
			want: path.Join(config.ProfilesRootPath, "ns", "file.json"),
			sp: &v1alpha1.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtSPNamespace",
			want: path.Join(config.ProfilesRootPath, "ns", "file.json"),
			sp: &v1alpha1.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "../../../../../ns",
				},
			},
		},
		{
			name: "AppendExtension",
			want: path.Join(config.ProfilesRootPath, "config-namespace", "file.json"),
			sp: &v1alpha1.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file",
					Namespace: "config-namespace",
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.sp.GetProfilePath()
			require.Equal(t, tc.want, got)
		})
	}
}

func TestUnionSyscalls(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		baseSyscalls    []*v1alpha1.Syscall
		appliedSyscalls []*v1alpha1.Syscall
		want            []*v1alpha1.Syscall
	}{
		{
			name:            "BothEmpty",
			baseSyscalls:    []*v1alpha1.Syscall{},
			appliedSyscalls: []*v1alpha1.Syscall{},
			want:            []*v1alpha1.Syscall{},
		},
		{
			name:         "BaseEmpty",
			baseSyscalls: []*v1alpha1.Syscall{},
			appliedSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			want: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "AppliedEmpty",
			baseSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1alpha1.Syscall{},
			want: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "UniqueActions",
			baseSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("bar"),
				},
			},
			want: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("bar"),
				},
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "OverlappingActionsWithUniqueNames",
			baseSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
			},
			appliedSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"d", "e", "f"},
					Action: seccomp.Action("foo"),
				},
			},
			want: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c", "d", "e", "f"},
					Action: seccomp.Action("foo"),
				},
			},
		},
		{
			name: "OverlappingActionsWithOverlappingNames",
			baseSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"a", "b", "c"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
			},
			appliedSyscalls: []*v1alpha1.Syscall{
				{
					Names:  []string{"b", "c", "d"},
					Action: seccomp.Action("foo"),
				},
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
			},
			want: []*v1alpha1.Syscall{
				{
					Names:  []string{"x", "y", "z"},
					Action: seccomp.Action("bar"),
				},
				{
					Names:  []string{"a", "b", "c", "d"},
					Action: seccomp.Action("foo"),
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := unionSyscalls(tc.baseSyscalls, tc.appliedSyscalls)
			for i := range got {
				sort.Strings(got[i].Names)
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].Action < got[j].Action
			})
			require.Equal(t, tc.want, got)
		})
	}
}
