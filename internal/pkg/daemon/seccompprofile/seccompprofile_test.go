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
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/containers/common/pkg/seccomp"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func TestReconcile(t *testing.T) {
	t.Parallel()

	name := "cool-profile"
	namespace := "cool-namespace"
	errOops := errors.New("oops")

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
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr:    nil,
		},
		{
			name: "ErrGetProfileIfSeccompEnabled",
			rec: &Reconciler{
				client: &util.MockClient{
					MockGet: util.NewMockGetFn(errOops),
				},
				record:  record.NewFakeRecorder(10),
				log:     log.Log,
				metrics: metrics.New(),
			},
			req:        reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}},
			wantResult: reconcile.Result{},
			wantErr: func() error {
				if seccomp.IsEnabled() {
					return fmt.Errorf("%s: %w", errGetProfile, errOops)
				}
				return nil
			}(),
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
	dir, err := os.MkdirTemp("", config.OperatorName)
	if err != nil {
		t.Error(fmt.Errorf("creating temp file for tests: %w", err))
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
			file, statErr := os.Stat(tc.fileName)
			gotFileCreated := file != nil

			if tc.wantErr == "" {
				require.NoError(t, gotErr)
				require.NoError(t, statErr)
			} else {
				require.Equal(t, tc.wantErr, gotErr.Error())
				require.Error(t, statErr)
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
		sp   *seccompprofileapi.SeccompProfile
	}{
		{
			name: "AppendNamespaceAndProfile",
			want: path.Join(config.ProfilesRootPath(), "config-namespace", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "config-namespace",
				},
			},
		},
		{
			name: "BlockTraversalAtProfileName",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "../../../../../file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtTargetName",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "ns",
				},
			},
		},
		{
			name: "BlockTraversalAtSPNamespace",
			want: path.Join(config.ProfilesRootPath(), "ns", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "file.json",
					Namespace: "../../../../../ns",
				},
			},
		},
		{
			name: "AppendExtension",
			want: path.Join(config.ProfilesRootPath(), "config-namespace", "file.json"),
			sp: &seccompprofileapi.SeccompProfile{
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

func TestAllowProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                  string
		allowedSyscalls       []string
		allowedSeccompActions []seccomp.Action
		profile               *seccompprofileapi.SeccompProfile
		want                  error
	}{
		{
			name:                  "EmptyProfile",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile:               &seccompprofileapi.SeccompProfile{},
			want:                  nil,
		},
		{
			name:                  "EmptyAllowedList",
			allowedSyscalls:       []string{},
			allowedSeccompActions: []seccomp.Action{},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{"a"},
						},
					},
				},
			},
			want: fmt.Errorf("%s: %s", errForbiddenSyscall, "a"),
		},
		{
			name:                  "ProfileWithEmptySyscalls",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                  "AllowProfile",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                  "RejectProfile",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{"d"},
						},
					},
				},
			},
			want: fmt.Errorf("%s: %s", errForbiddenSyscall, "d"),
		},
		{
			name:                  "AllAllowedActions",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{"a"},
						},
						{
							Action: seccomp.ActLog,
							Names:  []string{"b"},
						},
						{
							Action: seccomp.ActTrace,
							Names:  []string{"c"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                  "AllForbiddenActions",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActErrno,
							Names:  []string{"a"},
						},
						{
							Action: seccomp.ActTrap,
							Names:  []string{"d"},
						},
						{
							Action: seccomp.ActKillThread,
							Names:  []string{"e"},
						},
						{
							Action: seccomp.ActKillThread,
							Names:  []string{"f"},
						},
						{
							Action: seccomp.ActKillProcess,
							Names:  []string{"g"},
						},
						{
							Action: seccomp.ActKill,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:                  "AllowedAll",
			allowedSyscalls:       []string{"a"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccomp.ActAllow,
				},
			},
			want: fmt.Errorf(errForbiddenProfile),
		},
		{
			name:                  "DeniedAll",
			allowedSyscalls:       []string{"a"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActAllow, seccomp.ActLog, seccomp.ActTrace},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccomp.ActErrno,
				},
			},
			want: nil,
		},
		{
			name:                  "DeniedAction",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccomp.Action{seccomp.ActErrno},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []*seccompprofileapi.Syscall{
						{
							Action: seccomp.ActAllow,
							Names:  []string{"a"},
						},
						{
							Action: seccomp.ActTrace,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: fmt.Errorf("%s: %s", errForbiddenAction, seccomp.ActErrno),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := allowProfile(tc.profile, tc.allowedSyscalls, tc.allowedSeccompActions)

			require.Equal(t, tc.want, got)
		})
	}
}

func TestAllowedSyscallsChangedPredicate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		event event.UpdateEvent
		want  bool
	}{
		{
			name:  "NilObjects",
			event: event.UpdateEvent{},
			want:  false,
		},
		{
			name: "FailedOldObjectAssertion",
			event: event.UpdateEvent{
				ObjectOld: &seccompprofileapi.SeccompProfile{},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{},
			},
			want: false,
		},
		{
			name: "FailedNewObjectAssertion",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{},
				ObjectNew: &seccompprofileapi.SeccompProfile{},
			},
			want: false,
		},
		{
			name: "DiffAllowedSyscallsLen",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a"},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "b"},
					},
				},
			},
			want: true,
		},
		{
			name: "DiffAllowedSyscalls",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "c"},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "b"},
					},
				},
			},
			want: true,
		},
		{
			name: "SameAllowedSyscalls",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "b"},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "b"},
					},
				},
			},
			want: false,
		},
		{
			name: "SameAllowedSyscallsOtherOrder",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"b", "a"},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						AllowedSyscalls: []string{"a", "b"},
					},
				},
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			predicate := AllowedSyscallsChangedPredicate{}
			got := predicate.Update(tc.event)

			require.Equal(t, tc.want, got)
		})
	}
}
