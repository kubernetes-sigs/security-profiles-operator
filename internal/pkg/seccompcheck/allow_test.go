/*
Copyright The Kubernetes Authors.

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

package seccompcheck

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

func TestAllowProfile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                  string
		allowedSyscalls       []string
		allowedSeccompActions []seccompprofileapi.Action
		profile               *seccompprofileapi.SeccompProfile
		want                  error
	}{
		{
			name:            "EmptyProfile",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{},
			want:    nil,
		},
		{
			name:                  "EmptyAllowedList",
			allowedSyscalls:       []string{},
			allowedSeccompActions: []seccompprofileapi.Action{},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{"a"},
						},
					},
				},
			},
			want: fmt.Errorf("%w: %s", ErrForbiddenSyscall, "a"),
		},
		{
			name:            "ProfileWithEmptySyscalls",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:            "AllowProfile",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:            "RejectProfile",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{"d"},
						},
					},
				},
			},
			want: fmt.Errorf("%w: %s", ErrForbiddenSyscall, "d"),
		},
		{
			name:            "AllAllowedActions",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{"a"},
						},
						{
							Action: seccompprofileapi.ActLog,
							Names:  []string{"b"},
						},
						{
							Action: seccompprofileapi.ActTrace,
							Names:  []string{"c"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:            "AllForbiddenActions",
			allowedSyscalls: []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActErrno,
							Names:  []string{"a"},
						},
						{
							Action: seccompprofileapi.ActTrap,
							Names:  []string{"d"},
						},
						{
							Action: seccompprofileapi.ActKillThread,
							Names:  []string{"e"},
						},
						{
							Action: seccompprofileapi.ActKillThread,
							Names:  []string{"f"},
						},
						{
							Action: seccompprofileapi.ActKillProcess,
							Names:  []string{"g"},
						},
						{
							Action: seccompprofileapi.ActKill,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: nil,
		},
		{
			name:            "AllowedAll",
			allowedSyscalls: []string{"a"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccompprofileapi.ActAllow,
				},
			},
			want: ErrForbiddenProfile,
		},
		{
			name:            "DeniedAll",
			allowedSyscalls: []string{"a"},
			allowedSeccompActions: []seccompprofileapi.Action{
				seccompprofileapi.ActAllow, seccompprofileapi.ActLog, seccompprofileapi.ActTrace,
			},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					DefaultAction: seccompprofileapi.ActErrno,
				},
			},
			want: nil,
		},
		{
			name:                  "DeniedAction",
			allowedSyscalls:       []string{"a", "b", "c"},
			allowedSeccompActions: []seccompprofileapi.Action{seccompprofileapi.ActErrno},
			profile: &seccompprofileapi.SeccompProfile{
				Spec: seccompprofileapi.SeccompProfileSpec{
					Syscalls: []seccompprofileapi.Syscall{
						{
							Action: seccompprofileapi.ActAllow,
							Names:  []string{"a"},
						},
						{
							Action: seccompprofileapi.ActTrace,
							Names:  []string{"b"},
						},
					},
				},
			},
			want: fmt.Errorf("%w: %s", ErrForbiddenAction, seccompprofileapi.ActErrno),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := AllowProfile(tc.profile, tc.allowedSyscalls, tc.allowedSeccompActions)

			require.Equal(t, tc.want, got)
		})
	}
}

func TestAllowListChangedPredicate(t *testing.T) {
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
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a"}},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "b"}},
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
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "c"}},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "b"}},
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
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "b"}},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "b"}},
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
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"b", "a"}},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{AllowedSyscalls: []string{"a", "b"}},
					},
				},
			},
			want: false,
		},
		{
			name: "DiffAllowedSeccompActions",
			event: event.UpdateEvent{
				ObjectOld: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{
							AllowedSyscalls: []string{"a"},
						},
					},
				},
				ObjectNew: &spodapi.SecurityProfilesOperatorDaemon{
					Spec: spodapi.SPODSpec{
						Security: spodapi.SPODSecurityConfig{
							AllowedSyscalls: []string{"a"},
							AllowedSeccompActions: []seccompprofileapi.Action{
								seccompprofileapi.ActLog,
							},
						},
					},
				},
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			predicate := AllowListChangedPredicate{}
			got := predicate.Update(tc.event)

			require.Equal(t, tc.want, got)
		})
	}
}

func TestNotAllowed(t *testing.T) {
	t.Parallel()

	require.True(t, NotAllowed(fmt.Errorf("%w: read", ErrForbiddenSyscall)))
	require.True(t, NotAllowed(ErrForbiddenProfile))
	require.True(t, NotAllowed(fmt.Errorf("%w: SCMP_ACT_ERRNO", ErrForbiddenAction)))
	require.False(t, NotAllowed(errors.New("other")))
	require.False(t, NotAllowed(nil))
}

func testProfile(name, base string, syscalls ...string) *seccompprofileapi.SeccompProfile {
	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: seccompprofileapi.SeccompProfileSpec{
			BaseProfileName: base,
			DefaultAction:   seccompprofileapi.ActErrno,
			Syscalls: []seccompprofileapi.Syscall{{
				Action: seccompprofileapi.ActAllow,
				Names:  syscalls,
			}},
		},
	}
}

func syscallNames(syscalls []seccompprofileapi.Syscall) []string {
	names := make([]string, 0, len(syscalls))
	for _, s := range syscalls {
		names = append(names, s.Names...)
	}

	return names
}

func TestResolveLocalSyscalls(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, seccompprofileapi.AddToScheme(scheme))

	chain := make([]client.Object, 0, MaxBaseProfileDepth+1)
	for i := range MaxBaseProfileDepth + 1 {
		base := ""
		if i < MaxBaseProfileDepth {
			base = fmt.Sprintf("chain-%d", i+1)
		}

		chain = append(chain, testProfile(fmt.Sprintf("chain-%d", i), base, "exit"))
	}

	otherNamespace := testProfile("other-ns", "", "open")
	otherNamespace.Namespace = "other"

	objs := append([]client.Object{
		testProfile("base", "", "write"),
		testProfile("oci-child", "oci://registry/base:v1", "read"),
		otherNamespace,
	}, chain...)

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

	for _, tc := range []struct {
		name    string
		profile *seccompprofileapi.SeccompProfile
		want    []string
		wantErr string
	}{
		{
			name:    "no base profile",
			profile: testProfile("plain", "", "read"),
			want:    []string{"read"},
		},
		{
			name:    "local base profile",
			profile: testProfile("child", "base", "read"),
			want:    []string{"read", "write"},
		},
		{
			name:    "OCI base profile",
			profile: testProfile("child", "oci://registry/base:v1", "read"),
			wantErr: ErrOCIBaseProfile.Error(),
		},
		{
			name:    "OCI base profile deeper in the chain",
			profile: testProfile("child", "oci-child", "exit"),
			wantErr: ErrOCIBaseProfile.Error(),
		},
		{
			name:    "base profile in another namespace",
			profile: testProfile("child", "other-ns", "read"),
			wantErr: "not found",
		},
		{
			name:    "chain too long",
			profile: testProfile("child", "chain-0", "read"),
			wantErr: "max recursion level",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ResolveLocalSyscalls(t.Context(), cli, tc.profile)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.ElementsMatch(t, tc.want, syscallNames(got))
		})
	}
}
