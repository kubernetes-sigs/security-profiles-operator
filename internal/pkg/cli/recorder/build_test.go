//go:build linux && !no_bpf

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

package recorder

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/cli-runtime/pkg/printers"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder/recorderfakes"
)

func newBuildRecorder(typ Type) (*Recorder, *recorderfakes.FakeImpl) {
	mock := &recorderfakes.FakeImpl{}

	options := Default()
	options.typ = typ
	options.baseSyscalls = []string{"read", "exit"}

	sut := New(options)
	sut.impl = mock

	return sut, mock
}

func TestBuildProfileRaw(t *testing.T) {
	t.Parallel()

	sut, mock := newBuildRecorder(TypeRawSeccomp)
	out := &bytes.Buffer{}

	require.NoError(t, sut.buildProfile(out, []string{"write", "read"}))
	require.Equal(t, 0, mock.PrintObjCallCount())

	spec := seccompprofileapi.SeccompProfileSpec{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &spec))

	arch, err := sut.goArchToSeccompArch(runtime.GOARCH)
	require.NoError(t, err)

	// The base syscalls are added once and the names get sorted.
	require.Equal(t, seccompprofileapi.SeccompProfileSpec{
		DefaultAction: seccompprofileapi.ActErrno,
		Architectures: []seccompprofileapi.Arch{arch},
		Syscalls: []seccompprofileapi.Syscall{{
			Action: seccompprofileapi.ActAllow,
			Names:  []string{"exit", "read", "write"},
		}},
	}, spec)
}

func TestBuildProfileCRD(t *testing.T) {
	t.Parallel()

	sut, mock := newBuildRecorder(TypeSeccomp)
	out := &bytes.Buffer{}

	require.NoError(t, sut.buildProfile(out, []string{"write"}))
	require.Equal(t, 1, mock.PrintObjCallCount())

	_, obj, writer := mock.PrintObjArgsForCall(0)
	require.Same(t, out, writer)

	profile, ok := obj.(*seccompprofileapi.SeccompProfile)
	require.True(t, ok)
	require.Equal(t, "SeccompProfile", profile.Kind)
	require.Equal(t, seccompprofileapi.GroupVersion.String(), profile.APIVersion)
	require.Equal(t, filepath.Base(sut.options.commandOptions.Command()), profile.Name)
	require.Equal(t, seccompprofileapi.ActErrno, profile.Spec.DefaultAction)
	require.Equal(t, []string{"exit", "read", "write"}, profile.Spec.Syscalls[0].Names)

	// The real printer produces a YAML profile CRD.
	yaml := &bytes.Buffer{}
	require.NoError(t, (&printers.YAMLPrinter{}).PrintObj(profile, yaml))
	require.Contains(t, yaml.String(), "kind: SeccompProfile")
	require.Contains(t, yaml.String(), "defaultAction: SCMP_ACT_ERRNO")
}

func TestBuildProfileWithoutBaseSyscalls(t *testing.T) {
	t.Parallel()

	sut, _ := newBuildRecorder(TypeRawSeccomp)
	sut.options.baseSyscalls = nil
	out := &bytes.Buffer{}

	require.NoError(t, sut.buildProfile(out, []string{"write"}))

	spec := seccompprofileapi.SeccompProfileSpec{}
	require.NoError(t, json.Unmarshal(out.Bytes(), &spec))
	require.Equal(t, []string{"write"}, spec.Syscalls[0].Names)
}

func appArmorSpec() *apparmorprofileapi.AppArmorProfileSpec {
	return &apparmorprofileapi.AppArmorProfileSpec{
		Mode: apparmorprofileapi.AppArmorModeEnforce,
		Abstract: apparmorprofileapi.AppArmorAbstract{
			Executable: &apparmorprofileapi.AppArmorExecutablesRules{
				AllowedExecutables: []string{"/usr/bin/echo"},
			},
		},
	}
}

func TestBuildAppArmorProfileCRD(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		typ       Type
		separator bool
	}{
		{typ: TypeApparmor},
		{typ: TypeAll, separator: true},
	} {
		t.Run(string(tc.typ), func(t *testing.T) {
			t.Parallel()

			sut, mock := newBuildRecorder(tc.typ)
			out := &bytes.Buffer{}

			require.NoError(t, sut.buildAppArmorProfileCRD(out, appArmorSpec()))
			require.Equal(t, 1, mock.PrintObjCallCount())

			_, obj, _ := mock.PrintObjArgsForCall(0)
			profile, ok := obj.(*apparmorprofileapi.AppArmorProfile)
			require.True(t, ok)
			require.Equal(t, "AppArmorProfile", profile.Kind)
			require.Equal(t, apparmorprofileapi.GroupVersion.String(), profile.APIVersion)
			require.Equal(t, *appArmorSpec(), profile.Spec)

			// Combined output separates the AppArmor from the seccomp profile.
			if tc.separator {
				require.Equal(t, "\n---\n", out.String())

				return
			}

			require.Empty(t, out.String())
		})
	}
}

func TestBuildAppArmorProfileRaw(t *testing.T) {
	t.Parallel()

	sut, mock := newBuildRecorder(TypeRawAppArmor)
	out := &bytes.Buffer{}

	require.NoError(t, sut.buildAppArmorProfileRaw(out, appArmorSpec()))
	require.Equal(t, 0, mock.PrintObjCallCount())

	programName, err := filepath.Abs(sut.options.commandOptions.Command())
	require.NoError(t, err)

	require.Contains(t, out.String(), "profile ")
	require.Contains(t, out.String(), programName)
	require.Contains(t, out.String(), "/usr/bin/echo")
}
