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

package translator

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

// fuzzListSeparator separates the entries of a fuzzed list.
const fuzzListSeparator = "\x00"

// cilAllowLineRegexp matches an allow rule of a translated policy.
var cilAllowLineRegexp = regexp.MustCompile(`^\(allow process (\S+) \( (\S+) \( (.*) \){3}$`)

func fuzzList(entries string) []string {
	if entries == "" {
		return nil
	}

	return strings.Split(entries, fuzzListSeparator)
}

// FuzzObject2CIL translates profiles built from arbitrary names, inherits,
// types, classes and permissions. An accepted policy has to be a single
// block with balanced parentheses, consist of valid identifiers only and
// respect the default denylists.
func FuzzObject2CIL(f *testing.F) {
	for _, seed := range []struct {
		name, objInherit, systemInherits, ttype, class, perms string
		permissive                                            bool
	}{
		{"foo-bar", "", "container", "var_log_t", "file", "getattr\x00read\x00write\x00append", false},
		{"foo-bar", "", "container\x00net_container", "var_log_t", "dir", "open\x00read", true},
		{"foo-bar_1", "", "container\x00net_container", selinuxprofileapi.AllowSelf, "tcp_socket", "listen", false},
		{"foo", "bar", "", "other.process", "unix_stream_socket", "connectto", false},
		{"foo", "", "", "var_log_t", "file ( read ))) (allow process shadow_t (file", "read", false},
		{"foo", "", "", "var_log_t", " security", "setenforce", false},
		{"foo", "", "", "var_log_t", "security\n", "load_policy", false},
		{"foo", "", "", "var_log_t (file (read))) (allow process shadow_t", "file", "read", false},
		{"foo", "", "", "var_log_t", "file", "read ))) (allow process shadow_t (file (read", false},
		{"foo.bar", "", "", "var_log_t", "file", "read", false},
		{"1foo", "", "", "var_log_t", "file", "read", false},
		{"foo", "", "container) (allow process shadow_t (file (read)))", "var_log_t", "file", "read", false},
		{"foo", "bar baz", "", "var_log_t", "file", "read", false},
		{"foo", "a/b", "", "shadow_t", "file", "read", false},
		{"foo", "", "", "var_log_t", "security", "read", false},
		{"foo", "", "", "var_log_t", "file", "relabelto", false},
		{"foo", "", "", "var_log_t", "file", "", false},
	} {
		f.Add(
			seed.name,
			seed.objInherit,
			seed.systemInherits,
			seed.ttype,
			seed.class,
			seed.perms,
			seed.permissive,
		)
	}

	f.Fuzz(func(
		t *testing.T, name, objInherit, systemInherits, ttype, class, perms string, permissive bool,
	) {
		sp := &selinuxprofileapi.SelinuxProfile{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: selinuxprofileapi.SelinuxProfileSpec{
				Allow: selinuxprofileapi.Allow{
					selinuxprofileapi.LabelKey(ttype): {
						selinuxprofileapi.ObjectClassKey(class): fuzzList(perms),
					},
				},
			},
		}

		if permissive {
			sp.Spec.Mode = selinuxprofileapi.SelinuxModePermissive
		}

		var objInherits []selinuxprofileapi.SelinuxProfileObject

		if objInherit != "" {
			objInherits = append(objInherits, &selinuxprofileapi.SelinuxProfile{
				ObjectMeta: metav1.ObjectMeta{Name: objInherit},
			})
		}

		policy, err := Object2CIL(fuzzList(systemInherits), objInherits, sp, nil)
		if err != nil {
			require.Empty(t, policy)

			return
		}

		require.Regexp(t, blockNameRegexp, name)
		requireWellFormedCIL(t, name, policy)
	})
}

// requireWellFormedCIL verifies the structure and the identifiers of a
// translated policy.
func requireWellFormedCIL(t *testing.T, name, policy string) {
	t.Helper()

	require.True(t, strings.HasPrefix(policy, "(block "+name+"\n"), policy)
	require.True(t, strings.HasSuffix(policy, "\n)\n"), policy)

	// The parentheses are balanced and only the last one closes the block.
	depth := 0

	for i, c := range policy {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			require.GreaterOrEqual(t, depth, 0, policy)

			if depth == 0 {
				require.Equal(t, len(policy)-2, i, "block closed early: %s", policy)
			}
		}
	}

	require.Zero(t, depth, policy)

	// Every token has to pass the validation of identifiers.
	tokens := strings.FieldsFunc(policy, func(r rune) bool {
		return r == '(' || r == ')' || r == ' ' || r == '\n'
	})
	for _, token := range tokens {
		require.Regexp(t, identifierRegexp, token)
	}

	denied := deniedOptionsFromOpts(nil)

	for line := range strings.SplitSeq(strings.TrimSuffix(policy, "\n"), "\n") {
		if !strings.HasPrefix(line, "(allow ") {
			continue
		}

		match := cilAllowLineRegexp.FindStringSubmatch(line)
		require.NotNil(t, match, line)
		require.NotContains(t, denied.deniedTypes, match[1])
		require.NotContains(t, denied.deniedClasses, match[2])

		for perm := range strings.FieldsSeq(match[3]) {
			require.NotContains(t, denied.deniedPermissions, perm)
		}
	}
}
