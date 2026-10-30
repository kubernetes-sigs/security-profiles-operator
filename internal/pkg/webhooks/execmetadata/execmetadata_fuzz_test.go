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

package execmetadata

import (
	"encoding/json"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

// fuzzUID is the request UID used by the fuzz tests. The API server sets
// UUIDs, so the UID is not fuzzed.
const fuzzUID = "0f6c5b6e-3c4f-4c1e-9a43-6a3c1f1d2e3f"

func fuzzRequest(subResource string, object, oldObject []byte) *admission.Request {
	return &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:         types.UID(fuzzUID),
		SubResource: subResource,
		Object:      runtime.RawExtension{Raw: object},
		OldObject:   runtime.RawExtension{Raw: oldObject},
	}}
}

// FuzzGetPodExecPatch feeds arbitrary pod exec options into the exec patch.
// The patched command runs the command of the options with the request UID,
// see requireExecRequestUID.
func FuzzGetPodExecPatch(f *testing.F) {
	for _, seed := range []string{
		`{"command":["sh","-c","true"],"container":"app"}`,
		`{"command":["env","` + config.ExecRequestUIDEnvKey + `=old","sh"]}`,
		`{"command":["` + config.ExecRequestUIDEnvKey + `=a\nb"]}`,
		`{"command":["env","` + config.ExecRequestUIDEnvKey + `=a\nb","sh"]}`,
		`{"command":["sh","-c","true","` + config.ExecRequestUIDEnvKey + `=x"]}`,
		`{"command":["env","-i","` + config.ExecRequestUIDEnvKey + `=x","sh"]}`,
		`{"command":["env","A=1","env","-u","` + config.ExecRequestUIDEnvKey + `","sh"]}`,
		`{"command":["/usr/bin/env","--","-i"]}`,
		`{"command":["env","-S","` + config.ExecRequestUIDEnvKey + `=x sh"]}`,
		`{"command":[]}`,
		`{"command":null}`,
		`{}`,
		`[]`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}

	handler := Handler{log: logr.Discard()}

	f.Fuzz(func(t *testing.T, object []byte) {
		patches, err := handler.getPodExecPatch(fuzzRequest("", object, nil))
		if err != nil {
			return
		}

		var options corev1.PodExecOptions
		require.NoError(t, json.Unmarshal(object, &options))

		require.Len(t, patches, 1)
		require.Equal(t, "add", patches[0].Operation)
		require.Equal(t, "/command", patches[0].Path)

		command, ok := patches[0].Value.([]string)
		require.True(t, ok)

		requireExecRequestUID(t, options.Command, command)
	})
}

func TestSetExecRequestUIDRunsWithTheUID(t *testing.T) {
	t.Parallel()

	const key = config.ExecRequestUIDEnvKey

	for name, command := range map[string][]string{
		"no env":               {"sh", "-c", "true"},
		"assignments":          {"A=1", key + "=fake", "sh"},
		"option as command":    {"-i", "sh"},
		"ignore environment":   {"env", "-i", key + "=fake", "sh"},
		"unset":                {"env", "-u", key, "--unset=" + key, "sh"},
		"combined options":     {"env", "-vu" + key, "-iC", "/", "sh"},
		"nested env":           {"env", "A=1", "env", key + "=fake", "sh"},
		"nested env unsetting": {"env", key + "=fake", "env", "-u" + key, "sh"},
		"end of options":       {"env", "--", key + "=fake", "-i"},
		"lone dash":            {"env", "-", "sh"},
		"lone dash after --":   {"env", "--", "-", "HOME=/", "sh"},
		"split string":         {"env", "-S", key + "=fake sh"},
		"chdir to assignment":  {"env", "-C", key + "=fake", "id"},
		"assignment in value":  {"env", "X=a " + key + "=fake", "id"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			requireExecRequestUID(t, command, setExecRequestUID(slices.Clone(command), fuzzUID))
		})
	}
}

// requireExecRequestUID asserts that the patched command runs what the
// original one runs with the same environment, apart from the request UID,
// according to simulateEnv. A command which is not an env command runs
// through one, which takes its leading arguments with a "=" for assignments
// and a leading "-" for -i. An original command with an option the
// simulation does not know has to get an env command which sets the UID
// prepended. The JSON enricher reads the UID back from the patched command
// with EnvCommandRequestUID.
func requireExecRequestUID(t *testing.T, original, patched []string) {
	t.Helper()

	uid, ok := EnvCommandRequestUID(patched)
	require.True(t, ok, "%q", patched)
	require.Equal(t, fuzzUID, uid, "%q", patched)

	assignment := config.ExecRequestUIDEnvKey + "=" + fuzzUID

	throughEnv := original
	if len(original) == 0 || path.Base(original[0]) != "env" {
		throughEnv = append([]string{"env", "--"}, original...)
	}

	wantEnv, wantCommand, known := simulateEnv(throughEnv)
	if !known {
		require.Equal(t, append([]string{"env", assignment}, original...), patched)

		return
	}

	gotEnv, gotCommand, known := simulateEnv(patched)
	require.True(t, known, "%q", patched)
	require.Equal(t, fuzzUID, gotEnv[config.ExecRequestUIDEnvKey], "%q", patched)

	delete(wantEnv, config.ExecRequestUIDEnvKey)
	delete(gotEnv, config.ExecRequestUIDEnvKey)
	require.Equal(t, wantEnv, gotEnv, "%q", patched)
	require.True(t, slices.Equal(wantCommand, gotCommand), "%q runs %q", patched, gotCommand)
}

// envOptionArgs are the options of GNU env, and whether they take an
// argument, by their short and long names. -S splits its argument into more
// arguments, which the simulation does not do.
var envOptionArgs = map[string]bool{
	"i": false, "ignore-environment": false,
	"0": false, "null": false,
	"v": false, "debug": false,
	"u": true, "unset": true,
	"C": true, "chdir": true,
	"S": true, "split-string": true,
}

// envOptionNames maps the long names of the options to their short ones.
var envOptionNames = map[string]string{
	"ignore-environment": "i", "null": "0", "debug": "v",
	"unset": "u", "chdir": "C", "split-string": "S",
}

// simulateEnv runs the env commands the command starts with, like GNU env
// with getopt, on an environment which has the request UID variable and
// others set. It returns the environment of the command they run, and that
// command. It returns false if an option is not known, takes an argument it
// does not get, or is -S.
func simulateEnv(command []string) (env map[string]string, run []string, known bool) {
	env = map[string]string{
		config.ExecRequestUIDEnvKey: "inherited",
		"HOME":                      "/root",
		"PATH":                      "/bin",
	}
	args := command

	for len(args) > 0 && path.Base(args[0]) == "env" {
		opts, rest, ok := getoptEnv(args[1:])
		if !ok {
			return nil, nil, false
		}

		args = rest

		// After the options, a lone "-" ignores the environment as well.
		if len(args) > 0 && args[0] == "-" {
			opts = append(opts, envOpt{name: "i"})
			args = args[1:]
		}

		for _, opt := range opts {
			switch opt.name {
			case "i":
				clear(env)
			case "u":
				delete(env, opt.value)
			case "S":
				return nil, nil, false
			}
		}

		for len(args) > 0 && strings.Contains(args[0], "=") {
			name, value, _ := strings.Cut(args[0], "=")
			env[name] = value
			args = args[1:]
		}
	}

	return env, args, true
}

// envOpt is an option of env by its short name, with its argument.
type envOpt struct {
	name, value string
}

// getoptEnv parses the options of env like getopt with "+": they end at the
// first argument which is not one, or after "--". It returns the options and
// the arguments after them, or false for an invalid option.
func getoptEnv(args []string) (opts []envOpt, rest []string, ok bool) {
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' {
		arg := args[0]
		args = args[1:]

		if arg == "--" {
			break
		}

		var parsed []envOpt

		if long, isLong := strings.CutPrefix(arg, "--"); isLong {
			parsed, args, ok = getoptEnvLong(long, args)
		} else {
			parsed, args, ok = getoptEnvShort(arg[1:], args)
		}

		if !ok {
			return nil, nil, false
		}

		opts = append(opts, parsed...)
	}

	return opts, args, true
}

// getoptEnvLong parses a long option without its leading "--".
func getoptEnvLong(long string, args []string) ([]envOpt, []string, bool) {
	name, value, inline := strings.Cut(long, "=")

	takesArg, ok := envOptionArgs[name]
	if !ok || len(name) == 1 || (inline && !takesArg) {
		return nil, nil, false
	}

	if takesArg && !inline {
		if len(args) == 0 {
			return nil, nil, false
		}

		value, args = args[0], args[1:]
	}

	return []envOpt{{name: envOptionNames[name], value: value}}, args, true
}

// getoptEnvShort parses the short options of an argument without its leading
// "-". An option which takes an argument takes the rest of the argument, or
// the next one.
func getoptEnvShort(short string, args []string) ([]envOpt, []string, bool) {
	var opts []envOpt

	for short != "" {
		name := short[:1]
		short = short[1:]

		takesArg, ok := envOptionArgs[name]
		if !ok {
			return nil, nil, false
		}

		if !takesArg {
			opts = append(opts, envOpt{name: name})

			continue
		}

		if short == "" {
			if len(args) == 0 {
				return nil, nil, false
			}

			short, args = args[0], args[1:]
		}

		opts = append(opts, envOpt{name: name, value: short})
		short = ""
	}

	return opts, args, true
}

// FuzzGetPodPatch feeds arbitrary pods into the pod patch, for node debugging
// pods as well as ephemeral containers. Every patch adds an env list which
// ends with the request UID.
func FuzzGetPodPatch(f *testing.F) {
	for _, seed := range []struct {
		subResource, object, oldObject string
	}{
		{"", `{"spec":{"containers":[{"name":"debugger"}]}}`, ""},
		{"", `{"spec":{"containers":[{"name":"debugger","env":[{"name":"` + config.ExecRequestUIDEnvKey + `"}]}]}}`, ""},
		{"", `{"spec":{"containers":[]}}`, ""},
		{
			utils.EphemeralContainersSubResource,
			`{"spec":{"ephemeralContainers":[{"name":"a"},{"name":"b"}]},` +
				`"status":{"ephemeralContainerStatuses":[{"name":"a"}]}}`,
			`{"spec":{"ephemeralContainers":[{"name":"a"}]}}`,
		},
		{utils.EphemeralContainersSubResource, `{"spec":{"ephemeralContainers":[{"name":"a"}]}}`, `[`},
		{utils.EphemeralContainersSubResource, `{}`, ""},
		{"status", `{}`, ""},
		{"", `null`, ""},
		{"", ``, ""},
	} {
		f.Add(seed.subResource, []byte(seed.object), []byte(seed.oldObject))
	}

	handler := Handler{log: logr.Discard()}

	f.Fuzz(func(t *testing.T, subResource string, object, oldObject []byte) {
		patches, err := handler.getPodPatch(fuzzRequest(subResource, object, oldObject))
		if err != nil {
			return
		}

		for _, patch := range patches {
			require.Equal(t, "add", patch.Operation)
			require.True(t, strings.HasSuffix(patch.Path, "/env"), patch.Path)

			env, ok := patch.Value.([]corev1.EnvVar)
			require.True(t, ok)
			require.NotEmpty(t, env)
			require.Equal(
				t,
				corev1.EnvVar{Name: config.ExecRequestUIDEnvKey, Value: fuzzUID},
				env[len(env)-1],
			)
		}
	})
}
