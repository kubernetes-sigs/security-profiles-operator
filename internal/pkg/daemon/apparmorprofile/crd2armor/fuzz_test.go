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

package crd2armor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
)

// fuzzListSeparator separates the entries of a fuzzed list. It is not
// allowed in any entry, so it cannot hide an invalid one.
const fuzzListSeparator = "\x00"

// fuzzProfileInput is the fuzzed input of a profile generation.
type fuzzProfileInput struct {
	name, readOnly, writeOnly, readWrite, executables, libraries, capabilities string
	complain, raw, tcp, udp                                                    bool
}

// fuzzProfileSeeds are the inputs of the generation test table.
var fuzzProfileSeeds = []fuzzProfileInput{
	{name: "EnforceModeWithDeny", readOnly: "/etc/passwd"},
	{name: "ComplainModeWithoutDeny", readOnly: "/etc/passwd", complain: true},
	{name: "NormalizedCapabilities", capabilities: " NET_ADMIN\x00Sys_Rawio "},
	{name: "my-app_profile.v1"},
	{name: "/path/to/my/profile"},
	{name: "my profile"},
	{name: "profile\n  audit network inet,"},
	{readOnly: "/proc/@{pid}/cgroup\x00/@{HOME}/.bashrc"},
	{readOnly: "/var/log/**\x00/etc/nginx/conf.d/*.conf\x00/lib/tls/i686/cmov/lib*.so?"},
	{readOnly: "/opt/my-app/v1.2+3/run_app\x00/My Documents/test file"},
	{
		executables: "/opt/my app/bin", libraries: "/opt/my app/lib.so",
		readOnly: "/My Documents/test file\x00/etc/passwd", writeOnly: "/var/log/my app.log",
		readWrite: "/tmp/@{pid}/a b/*",
	},
	{readOnly: "/"},
	{name: "PtraceEnforce", readOnly: "ptrace (read),\x00/etc/passwd", writeOnly: "ptrace (Read),"},
	{name: "PtraceComplain", readWrite: "ptrace (readby),  # comment", complain: true},
	{readOnly: "ptrace (everything),"},
	{executables: "ptrace (read),"},
	{readOnly: "ptrace (read) /etc/shadow r,"},
	{readOnly: "usr/bin/nginx"},
	{readOnly: `/etc/"passwd"`},
	{readOnly: "/usr/bin/$(whoami)"},
	{readOnly: "/usr/bin/nginx, /etc/passwd"},
	{readOnly: "/usr/bin/nginx ; rm -rf /"},
	{executables: "/usr/bin/nginx"},
	{libraries: "/lib/x86_64-linux-gnu/**"},
	{executables: "/var/log/app.log\n  audit network inet,"},
	{libraries: `/var/log/"app".log`},
	{executables: "/usr/bin/../etc/shadow"},
	{capabilities: "chown"},
	{capabilities: "DAC_OVERRIDE"},
	{capabilities: "CAP_CHOWN"},
	{capabilities: "chown, net_admin"},
	{capabilities: "audit"},
	{name: "net", raw: true, tcp: true, udp: true},
	{name: "net-deny", tcp: true},
	{name: "brace", readOnly: "/a/{b}/c"},
	{name: "systemd-unit", readOnly: "/sys/fs/cgroup/system.slice/foo@1.service\x00/a@b"},
}

func fuzzList(entries string) []string {
	if entries == "" {
		return nil
	}

	// Empty entries are kept: the validation has to reject them.
	return strings.Split(entries, fuzzListSeparator)
}

func (in *fuzzProfileInput) abstract() *apparmorprofileapi.AppArmorAbstract {
	abstract := &apparmorprofileapi.AppArmorAbstract{
		Network: &apparmorprofileapi.AppArmorNetworkRules{
			AllowRaw: &in.raw,
			Protocols: &apparmorprofileapi.AppArmorAllowedProtocols{
				AllowTCP: &in.tcp,
				AllowUDP: &in.udp,
			},
		},
	}

	if in.executables != "" || in.libraries != "" {
		abstract.Executable = &apparmorprofileapi.AppArmorExecutablesRules{
			AllowedExecutables: fuzzList(in.executables),
			AllowedLibraries:   fuzzList(in.libraries),
		}
	}

	if in.readOnly != "" || in.writeOnly != "" || in.readWrite != "" {
		abstract.Filesystem = &apparmorprofileapi.AppArmorFsRules{
			ReadOnlyPaths:  fuzzList(in.readOnly),
			WriteOnlyPaths: fuzzList(in.writeOnly),
			ReadWritePaths: fuzzList(in.readWrite),
		}
	}

	if in.capabilities != "" {
		abstract.Capability = &apparmorprofileapi.AppArmorCapabilityRules{
			AllowedCapabilities: fuzzList(in.capabilities),
		}
	}

	return abstract
}

func (in *fuzzProfileInput) mode() apparmorprofileapi.AppArmorMode {
	if in.complain {
		return apparmorprofileapi.AppArmorModeComplain
	}

	return apparmorprofileapi.AppArmorModeEnforce
}

// unbalancedBraces reports whether s closes a brace it did not open or leaves
// one open.
func unbalancedBraces(s string) bool {
	depth := 0

	for _, c := range s {
		switch c {
		case '{':
			depth++
		case '}':
			depth--

			if depth < 0 {
				return true
			}
		}
	}

	return depth != 0
}

// topLevelCommas counts the commas of s outside of alternations, which are
// the ends of rules.
func topLevelCommas(s string) int {
	commas, depth := 0, 0

	for _, c := range s {
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				commas++
			}
		}
	}

	return commas
}

// FuzzGenerateProfile generates profiles from arbitrary names, paths and
// capabilities. A profile which passes the validation has to be structurally
// sound: a single profile block which is closed at its end, and nothing from
// the input can end a rule early or start a new one.
func FuzzGenerateProfile(f *testing.F) {
	for i := range fuzzProfileSeeds {
		in := &fuzzProfileSeeds[i]
		f.Add(in.name, in.readOnly, in.writeOnly, in.readWrite, in.executables, in.libraries,
			in.capabilities, in.complain, in.raw, in.tcp, in.udp)
	}

	f.Fuzz(func(
		t *testing.T,
		name, readOnly, writeOnly, readWrite, executables, libraries, capabilities string,
		complain, raw, tcp, udp bool,
	) {
		in := fuzzProfileInput{
			name: name, readOnly: readOnly, writeOnly: writeOnly, readWrite: readWrite,
			executables: executables, libraries: libraries, capabilities: capabilities,
			complain: complain, raw: raw, tcp: tcp, udp: udp,
		}

		profile, err := GenerateProfile(in.name, in.mode(), in.abstract())
		if err != nil {
			require.Empty(t, profile)

			return
		}

		requireWellFormedProfile(t, profile)
	})
}

// requireWellFormedProfile verifies the structure of a generated profile.
func requireWellFormedProfile(t *testing.T, profile string) {
	t.Helper()

	profileLines, depth, closed := 0, 0, false

	for line := range strings.SplitSeq(profile, "\n") {
		trimmed := strings.TrimSpace(line)

		// Neither paths nor names can contain a comment character, so a
		// comment always comes from the template.
		if i := strings.Index(trimmed, " #"); i >= 0 {
			trimmed = strings.TrimSpace(trimmed[:i])
		}

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		require.False(t, closed, "content after the end of the profile: %q", line)

		switch {
		case strings.HasPrefix(trimmed, "profile "):
			profileLines++

			require.Zero(t, depth, "nested profile: %q", line)
			require.True(t, strings.HasSuffix(trimmed, "{"), "profile line: %q", line)
			require.Equal(t, 1, strings.Count(trimmed, "{"), "profile line: %q", line)
			require.NotContains(t, trimmed, "}")

			depth++

			continue
		case trimmed == "}":
			require.Equal(t, 1, depth, "unexpected end of block: %q", line)

			depth--
			closed = true

			continue
		}

		// A rule has to end with a comma, otherwise an input value
		// continues it on the next line, and every alternation it opens
		// has to be closed within it.
		require.Equal(t, 1, depth, "rule outside of the profile: %q", line)
		require.True(t, strings.HasSuffix(trimmed, ","), "unterminated rule: %q", line)
		require.False(t, unbalancedBraces(trimmed), "unbalanced braces: %q", line)
		require.Equal(t, 1, topLevelCommas(trimmed), "more than one rule: %q", line)
	}

	require.Equal(t, 1, profileLines)
	require.True(t, closed)
	require.Zero(t, depth)
}

// TestGenerateProfileApparmorParser verifies that apparmor_parser accepts the
// profiles generated from the fuzzing seeds which pass the validation.
func TestGenerateProfileApparmorParser(t *testing.T) {
	t.Parallel()

	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		t.Skip("apparmor_parser is not available")
	}

	for i := range fuzzProfileSeeds {
		in := fuzzProfileSeeds[i]
		if in.name == "" || strings.HasPrefix(in.name, "/") {
			// A path name is attached by path and only makes sense for spoc.
			in.name = "fuzz-seed"
		}

		profile, err := GenerateProfile(in.name, in.mode(), in.abstract())
		if err != nil {
			continue
		}

		t.Run(in.name, func(t *testing.T) {
			t.Parallel()

			file := filepath.Join(t.TempDir(), "profile")
			require.NoError(t, os.WriteFile(file, []byte(profile), 0o600))

			out, err := exec.CommandContext(t.Context(), parser, "-Q", "-K", file).CombinedOutput()
			require.NoError(t, err, "%s\n%s", out, profile)
		})
	}
}
