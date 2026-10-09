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

package manifests

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utiljson "k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/version"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/apiserver/pkg/cel/environment"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
)

const (
	baseDir     = "../../../deploy/base"
	examplesDir = "../../../examples"

	spodUser         = "system:serviceaccount:security-profiles-operator:spod"
	nodeNameClaim    = "authentication.kubernetes.io/node-name"
	recordingIDLabel = "spo.x-k8s.io/recording-id"
	profileIDLabel   = "spo.x-k8s.io/profile-id"
)

// profileTypes are the Go types of the profile kinds which the
// spo-spod-profiles policy covers.
var profileTypes = map[string]reflect.Type{
	"SeccompProfile":    reflect.TypeFor[seccompprofileapi.SeccompProfile](),
	"AppArmorProfile":   reflect.TypeFor[apparmorprofileapi.AppArmorProfile](),
	"SelinuxProfile":    reflect.TypeFor[selinuxprofileapi.SelinuxProfile](),
	"RawSelinuxProfile": reflect.TypeFor[selinuxprofileapi.RawSelinuxProfile](),
}

// readObjects returns the objects of the YAML documents of the file, with
// integers as int64 like the API server decodes them.
func readObjects(t *testing.T, path string) []map[string]any {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err)

	defer f.Close()

	decoder := utilyaml.NewYAMLOrJSONDecoder(f, 4096)

	var objects []map[string]any

	for {
		var raw json.RawMessage

		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return objects
		}

		require.NoError(t, err, path)

		obj := map[string]any{}
		require.NoError(t, utiljson.Unmarshal(raw, &obj), path)

		if len(obj) > 0 {
			objects = append(objects, obj)
		}
	}
}

// readPolicy returns the ValidatingAdmissionPolicy of the file of deploy/base
// and checks that a binding denies the requests which it rejects.
func readPolicy(t *testing.T, file string) *admissionregv1.ValidatingAdmissionPolicy {
	t.Helper()

	var (
		policy  *admissionregv1.ValidatingAdmissionPolicy
		binding *admissionregv1.ValidatingAdmissionPolicyBinding
	)

	for _, obj := range readObjects(t, filepath.Join(baseDir, file)) {
		switch obj["kind"] {
		case "ValidatingAdmissionPolicy":
			policy = &admissionregv1.ValidatingAdmissionPolicy{}
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(obj, policy))
		case "ValidatingAdmissionPolicyBinding":
			binding = &admissionregv1.ValidatingAdmissionPolicyBinding{}
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(obj, binding))
		}
	}

	require.NotNil(t, policy)
	require.NotNil(t, binding)
	require.Equal(t, policy.Name, binding.Spec.PolicyName)
	require.Equal(t,
		[]admissionregv1.ValidationAction{admissionregv1.Deny},
		binding.Spec.ValidationActions,
	)

	return policy
}

// request is an admission request, which evaluate turns into the variables
// of the CEL expressions.
type request struct {
	operation string
	kind      string
	namespace string
	username  string
	// nodes is the node name claim of the service account token.
	nodes     []any
	object    map[string]any
	oldObject map[string]any
}

// newEnv returns the CEL environment of the policies of the oldest supported
// Kubernetes version, which compiles the policies with the libraries of the
// version before.
func newEnv(t *testing.T) *cel.Env {
	t.Helper()

	envSet, err := environment.MustBaseEnvSet(version.MajorMinor(1, 29)).Extend(
		environment.VersionedOptions{
			IntroducedVersion: version.MajorMinor(1, 0),
			EnvOptions: []cel.EnvOption{
				cel.Variable("object", cel.DynType),
				cel.Variable("oldObject", cel.DynType),
				cel.Variable("request", cel.DynType),
				cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
			},
		},
	)
	require.NoError(t, err)

	return envSet.NewExpressionsEnv()
}

// evaluate evaluates the policy like the API server does and returns whether
// it admits the request. A request which does not match the policy is
// admitted. The API server evaluates the variables lazily, so a variable
// which fails is left out and only fails the expressions which use it.
func evaluate(
	t *testing.T,
	env *cel.Env,
	policy *admissionregv1.ValidatingAdmissionPolicy,
	req *request,
) bool {
	t.Helper()

	userInfo := map[string]any{"username": req.username}
	if req.nodes != nil {
		userInfo["extra"] = map[string]any{nodeNameClaim: req.nodes}
	}

	reqVar := map[string]any{
		"operation": req.operation,
		"kind":      map[string]any{"kind": req.kind},
		"userInfo":  userInfo,
	}
	if req.namespace != "" {
		reqVar["namespace"] = req.namespace
	}

	var object, oldObject any
	if req.object != nil {
		object = req.object
	}

	if req.oldObject != nil {
		oldObject = req.oldObject
	}

	variables := map[string]any{}
	activation := map[string]any{
		"object":    object,
		"oldObject": oldObject,
		"request":   reqVar,
		"variables": variables,
	}

	eval := func(expression string) (any, error) {
		ast, issues := env.Compile(expression)
		require.NoError(t, issues.Err(), expression)

		prg, err := env.Program(ast)
		require.NoError(t, err, expression)

		out, _, err := prg.Eval(activation)
		if err != nil {
			return nil, err
		}

		return out, nil
	}

	evalBool := func(expression string) bool {
		out, err := eval(expression)
		require.NoError(t, err, expression)

		value, ok := out.(interface{ Value() any }).Value().(bool)
		require.True(t, ok, expression)

		return value
	}

	for _, condition := range policy.Spec.MatchConditions {
		if !evalBool(condition.Expression) {
			return true
		}
	}

	for _, variable := range policy.Spec.Variables {
		if out, err := eval(variable.Expression); err == nil {
			variables[variable.Name] = out
		}
	}

	for _, validation := range policy.Spec.Validations {
		if !evalBool(validation.Expression) {
			return false
		}
	}

	return true
}

// deepCopy returns a deep copy of the JSON value.
func deepCopy(t *testing.T, value map[string]any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	require.NoError(t, err)

	out := map[string]any{}
	require.NoError(t, utiljson.Unmarshal(data, &out))

	return out
}

// applyDefaults applies the defaults of the CRDs to the spec of the profile,
// like the API server does for each object it decodes.
func applyDefaults(kind string, obj map[string]any) {
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		spec = map[string]any{}
		obj["spec"] = spec
	}

	setDefault := func(m map[string]any, key string, value any) {
		if _, ok := m[key]; !ok {
			m[key] = value
		}
	}

	setDefault(spec, "state", "Enabled")

	switch kind {
	case "AppArmorProfile":
		setDefault(spec, "mode", "Enforce")
	case "SelinuxProfile":
		setDefault(spec, "mode", "Enforcing")
		setDefault(spec, "inherit", []any{map[string]any{"name": "container"}})

		inherit, ok := spec["inherit"].([]any)
		if !ok {
			return
		}

		for _, item := range inherit {
			if ref, ok := item.(map[string]any); ok {
				setDefault(ref, "kind", "System")
			}
		}
	}
}

// roundTrip returns the profile the way a daemon writes it back: decoded into
// its Go type, encoded again and defaulted by the API server.
func roundTrip(t *testing.T, kind string, obj map[string]any) map[string]any {
	t.Helper()

	data, err := json.Marshal(obj)
	require.NoError(t, err)

	typed := reflect.New(profileTypes[kind]).Interface()
	require.NoError(t, json.Unmarshal(data, typed))

	data, err = json.Marshal(typed)
	require.NoError(t, err)

	out := map[string]any{}
	require.NoError(t, utiljson.Unmarshal(data, &out))

	applyDefaults(kind, out)

	return out
}

// profile returns a profile of the kind with the spec and labels.
func profile(kind string, spec, labels map[string]any) map[string]any {
	metadata := map[string]any{"name": "profile"}
	if labels != nil {
		metadata["labels"] = labels
	}

	return map[string]any{
		"apiVersion": "security-profiles-operator.x-k8s.io/v1",
		"kind":       kind,
		"metadata":   metadata,
		"spec":       spec,
	}
}

// fullSpecs set every field of the spec of each kind to a value which is not
// the zero value.
func fullSpecs() map[string]map[string]any {
	return map[string]map[string]any{
		"SeccompProfile": {
			"state":            "Enabled",
			"baseProfileName":  "runc-v1.2.0",
			"defaultAction":    "SCMP_ACT_ERRNO",
			"architectures":    []any{"SCMP_ARCH_X86_64"},
			"listenerPath":     "/var/run/security-profiles-operator/listener.sock",
			"listenerMetadata": "metadata",
			"flags":            []any{"SECCOMP_FILTER_FLAG_LOG"},
			"syscalls": []any{map[string]any{
				"names":    []any{"read"},
				"action":   "SCMP_ACT_ALLOW",
				"errnoRet": int64(1),
				"args": []any{map[string]any{
					"index":    int64(1),
					"value":    int64(2),
					"valueTwo": int64(3),
					"op":       "SCMP_CMP_EQ",
				}},
			}},
		},
		"AppArmorProfile": {
			"state": "Enabled",
			"mode":  "Enforce",
			"abstract": map[string]any{
				"executable": map[string]any{
					"allowedExecutables": []any{"/bin/sh"},
					"allowedLibraries":   []any{"/lib/libc.so.6"},
				},
				"filesystem": map[string]any{
					"readOnlyPaths":  []any{"/etc"},
					"writeOnlyPaths": []any{"/tmp"},
					"readWritePaths": []any{"/var"},
				},
				"network": map[string]any{
					"allowRaw": true,
					"allowedProtocols": map[string]any{
						"allowTcp": true,
						"allowUdp": true,
					},
				},
				"capability": map[string]any{
					"allowedCapabilities": []any{"net_bind_service"},
				},
				"ptrace": map[string]any{
					"allowedAccess": []any{"read"},
					"peer":          "peer",
				},
			},
		},
		"SelinuxProfile": {
			"state":   "Enabled",
			"mode":    "Enforcing",
			"inherit": []any{map[string]any{"kind": "System", "name": "container"}},
			"allow": map[string]any{
				"@self": map[string]any{"tcp_socket": []any{"listen"}},
			},
		},
		"RawSelinuxProfile": {
			"state":  "Enabled",
			"policy": "(allow process self (tcp_socket (listen)))",
		},
	}
}

// specPaths returns the paths of the fields of the Go type, with "[]" for
// the first item of a list. Maps are not descended into.
func specPaths(typ reflect.Type, prefix string) []string {
	var paths []string

	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")

		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}

		if field.Anonymous && name == "" {
			paths = append(paths, specPaths(fieldType, prefix)...)

			continue
		}

		path := prefix + name

		switch {
		case fieldType.Kind() == reflect.Struct:
			paths = append(paths, specPaths(fieldType, path+".")...)
		case fieldType.Kind() == reflect.Slice && fieldType.Elem().Kind() == reflect.Struct:
			paths = append(paths, specPaths(fieldType.Elem(), path+"[].")...)
		default:
			paths = append(paths, path)
		}
	}

	return paths
}

// fieldParent returns the map holding the field of the path and its key.
func fieldParent(
	t *testing.T,
	spec map[string]any,
	path string,
) (parent map[string]any, key string) {
	t.Helper()

	parent = spec
	segments := strings.Split(path, ".")

	for _, segment := range segments[:len(segments)-1] {
		name, isList := strings.CutSuffix(segment, "[]")

		value, ok := parent[name]
		require.True(t, ok, "%s is not set", path)

		if isList {
			list, ok := value.([]any)
			require.True(t, ok, path)
			require.NotEmpty(t, list, path)

			value = list[0]
		}

		parent, ok = value.(map[string]any)
		require.True(t, ok, path)
	}

	key = segments[len(segments)-1]
	_, ok := parent[key]
	require.True(t, ok, "%s is not set", path)

	return parent, key
}

// changeValue returns another value of the same type.
func changeValue(t *testing.T, value any) any {
	t.Helper()

	switch v := value.(type) {
	case string:
		return v + "x"
	case int64:
		return v + 1
	case bool:
		return !v
	case []any:
		return append(v, "x")
	case map[string]any:
		changed := map[string]any{"x": map[string]any{"file": []any{"read"}}}
		maps.Copy(changed, v)

		return changed
	}

	require.FailNow(t, "unexpected type", "%T", value)

	return nil
}

func TestSpodProfilesPolicySpecs(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	policy := readPolicy(t, "spod_profile_policy.yaml")
	recorded := map[string]any{
		recordingIDLabel:                   "recording",
		"spo.x-k8s.io/recording-namespace": "default",
	}

	for kind, typ := range profileTypes {
		specField, ok := typ.FieldByName("Spec")
		require.True(t, ok)

		paths := specPaths(specField.Type, "")
		require.NotEmpty(t, paths)

		for _, path := range paths {
			for _, mutation := range []string{"change", "remove"} {
				t.Run(kind+"/"+mutation+"/"+path, func(t *testing.T) {
					t.Parallel()

					spec := fullSpecs()[kind]
					newSpec := deepCopy(t, spec)

					// Each field has to be set in the full spec, so that
					// the policy has to detect a change of it.
					parent, key := fieldParent(t, newSpec, path)
					if mutation == "change" {
						parent[key] = changeValue(t, parent[key])
					} else {
						delete(parent, key)
					}

					update := func(labels map[string]any) *request {
						return &request{
							operation: "UPDATE",
							kind:      kind,
							username:  spodUser,
							object:    profile(kind, newSpec, labels),
							oldObject: profile(kind, spec, labels),
						}
					}

					require.False(t, evaluate(t, env, policy, update(nil)),
						"the spec of a profile which was not recorded got changed")

					require.Equal(t, kind != "RawSelinuxProfile",
						evaluate(t, env, policy, update(recorded)),
						"the spec of a recorded profile got changed")
				})
			}
		}
	}
}

func TestSpodProfilesPolicyRoundTrip(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	policy := readPolicy(t, "spod_profile_policy.yaml")

	// Fields which are set to their zero values, which the daemons drop when
	// writing a profile back.
	profiles := []map[string]any{
		profile("SeccompProfile", map[string]any{
			"baseProfileName":  "",
			"defaultAction":    "SCMP_ACT_ERRNO",
			"architectures":    []any{},
			"listenerPath":     "",
			"listenerMetadata": "",
			"flags":            []any{},
			"syscalls": []any{
				map[string]any{
					"names":    []any{"read"},
					"action":   "SCMP_ACT_ALLOW",
					"errnoRet": int64(0),
					"args": []any{map[string]any{
						"index":    int64(0),
						"value":    int64(0),
						"valueTwo": int64(0),
						"op":       "SCMP_CMP_EQ",
					}},
				},
				map[string]any{"names": []any{}, "action": "SCMP_ACT_LOG", "args": []any{}},
			},
		}, nil),
		profile("AppArmorProfile", map[string]any{}, nil),
		profile("AppArmorProfile", map[string]any{
			"abstract": map[string]any{
				"executable": map[string]any{
					"allowedExecutables": []any{},
					"allowedLibraries":   []any{},
				},
				"filesystem": map[string]any{},
				"network": map[string]any{
					"allowRaw":         false,
					"allowedProtocols": map[string]any{"allowTcp": false},
				},
				"capability": map[string]any{"allowedCapabilities": []any{}},
				"ptrace":     map[string]any{"allowedAccess": []any{}, "peer": ""},
			},
		}, nil),
		profile(
			"SelinuxProfile",
			map[string]any{"inherit": []any{}, "allow": map[string]any{}},
			nil,
		),
		profile("SelinuxProfile", map[string]any{
			"allow": map[string]any{"@self": map[string]any{"tcp_socket": []any{}}},
		}, nil),
	}

	// The daemons add their finalizer and the label of the node status to
	// the profile they read.
	check := func(stored map[string]any) {
		kind, ok := stored["kind"].(string)
		require.True(t, ok)
		require.Contains(t, profileTypes, kind)

		applyDefaults(kind, stored)

		written := roundTrip(t, kind, stored)
		metadata, ok := written["metadata"].(map[string]any)
		require.True(t, ok)

		metadata["finalizers"] = []any{"node-deleted"}
		metadata["labels"] = map[string]any{profileIDLabel: kind + "-profile"}

		require.True(t, evaluate(t, env, policy, &request{
			operation: "UPDATE",
			kind:      kind,
			username:  spodUser,
			object:    written,
			oldObject: stored,
		}), "%s %v", kind, stored["metadata"])
	}

	for _, stored := range profiles {
		check(stored)
	}

	for _, file := range []string{
		"apparmorprofile.yaml",
		"baseprofile-crun.yaml",
		"baseprofile-runc.yaml",
		"rawselinuxprofile.yaml",
		"seccompprofile.yaml",
		"selinuxprofile.yaml",
	} {
		for _, stored := range readObjects(t, filepath.Join(examplesDir, file)) {
			check(stored)
		}
	}
}

func TestSpodProfilesPolicyMetadata(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	policy := readPolicy(t, "spod_profile_policy.yaml")
	spec := func() map[string]any {
		return fullSpecs()["SeccompProfile"]
	}
	recorded := func() map[string]any {
		return map[string]any{
			recordingIDLabel:                   "recording",
			"spo.x-k8s.io/recording-namespace": "default",
		}
	}
	withMetadata := func(obj map[string]any, key string, value any) map[string]any {
		metadata, ok := obj["metadata"].(map[string]any)
		require.True(t, ok)

		metadata[key] = value

		return obj
	}

	for _, tc := range []struct {
		name     string
		req      *request
		admitted bool
	}{
		{
			name: "create recorded profile",
			req: &request{
				operation: "CREATE",
				kind:      "SeccompProfile",
				object:    profile("SeccompProfile", spec(), recorded()),
			},
			admitted: true,
		},
		{
			name: "create recorded raw SELinux profile",
			req: &request{
				operation: "CREATE",
				kind:      "RawSelinuxProfile",
				object:    profile("RawSelinuxProfile", fullSpecs()["RawSelinuxProfile"], recorded()),
			},
			admitted: false,
		},
		{
			name: "create profile which was not recorded",
			req: &request{
				operation: "CREATE",
				kind:      "SeccompProfile",
				object:    profile("SeccompProfile", spec(), map[string]any{recordingIDLabel: "recording"}),
			},
			admitted: false,
		},
		{
			name: "add finalizer and annotation",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: withMetadata(
					withMetadata(profile("SeccompProfile", spec(), nil), "finalizers", []any{"node-deleted"}),
					"annotations", map[string]any{"syscalls": "[]"},
				),
				oldObject: profile("SeccompProfile", spec(), nil),
			},
			admitted: true,
		},
		{
			name: "add profile ID label",
			req: &request{
				operation: "UPDATE",
				kind:      "AppArmorProfile",
				object: profile("AppArmorProfile", fullSpecs()["AppArmorProfile"],
					map[string]any{"team": "a", profileIDLabel: "id"}),
				oldObject: profile("AppArmorProfile", fullSpecs()["AppArmorProfile"],
					map[string]any{"team": "a"}),
			},
			admitted: true,
		},
		{
			name: "add partial label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: profile("SeccompProfile", spec(),
					map[string]any{"spo.x-k8s.io/partial": "true"}),
				oldObject: profile("SeccompProfile", spec(), nil),
			},
			admitted: false,
		},
		{
			name: "remove label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object:    profile("SeccompProfile", spec(), map[string]any{}),
				oldObject: profile("SeccompProfile", spec(), map[string]any{"team": "a"}),
			},
			admitted: false,
		},
		{
			name: "change label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object:    profile("SeccompProfile", spec(), map[string]any{"team": "b"}),
				oldObject: profile("SeccompProfile", spec(), map[string]any{"team": "a"}),
			},
			admitted: false,
		},
		{
			name: "add recording ID label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object:    profile("SeccompProfile", spec(), recorded()),
				oldObject: profile("SeccompProfile", spec(), nil),
			},
			admitted: false,
		},
		{
			name: "remove recording ID label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: profile("SeccompProfile", spec(),
					map[string]any{"spo.x-k8s.io/recording-namespace": "default"}),
				oldObject: profile("SeccompProfile", spec(), recorded()),
			},
			admitted: false,
		},
		{
			name: "change recording ID label",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: profile("SeccompProfile", spec(), map[string]any{
					recordingIDLabel:                   "other",
					"spo.x-k8s.io/recording-namespace": "default",
				}),
				oldObject: profile("SeccompProfile", spec(), recorded()),
			},
			admitted: false,
		},
		{
			name: "add labels to recorded profile",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: profile("SeccompProfile", spec(), map[string]any{
					recordingIDLabel:                   "recording",
					"spo.x-k8s.io/recording-namespace": "default",
					"spo.x-k8s.io/container-id":        "container",
					"spo.x-k8s.io/partial":             "true",
				}),
				oldObject: profile("SeccompProfile", spec(), map[string]any{recordingIDLabel: "recording"}),
			},
			admitted: true,
		},
		{
			name: "add owner reference",
			req: &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				object: withMetadata(profile("SeccompProfile", spec(), nil), "ownerReferences", []any{
					map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "name": "gone", "uid": "uid"},
				}),
				oldObject: profile("SeccompProfile", spec(), nil),
			},
			admitted: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.req.username = spodUser
			require.Equal(t, tc.admitted, evaluate(t, env, policy, tc.req))
		})
	}
}

func TestSpodProfilesPolicyUsers(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	policy := readPolicy(t, "spod_profile_policy.yaml")
	weakened := fullSpecs()["SeccompProfile"]
	weakened["defaultAction"] = "SCMP_ACT_ALLOW"

	for username, admitted := range map[string]bool{
		spodUser:                           false,
		"system:serviceaccount:other:spod": false,
		"system:serviceaccount:security-profiles-operator:security-profiles-operator": true,
		"system:serviceaccount:security-profiles-operator:spod-other":                 true,
		"spod":       true,
		"kube:admin": true,
	} {
		t.Run(username, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, admitted, evaluate(t, env, policy, &request{
				operation: "UPDATE",
				kind:      "SeccompProfile",
				username:  username,
				object:    profile("SeccompProfile", weakened, nil),
				oldObject: profile("SeccompProfile", fullSpecs()["SeccompProfile"], nil),
			}))
		})
	}
}

func TestSpodJobsPolicy(t *testing.T) {
	t.Parallel()

	env := newEnv(t)
	policy := readPolicy(t, "spod_job_policy.yaml")
	job := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata":   map[string]any{"name": "reload", "namespace": "security-profiles-operator"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"serviceAccountName": "spod",
			"nodeName":           "node-a",
			"containers":         []any{map[string]any{"name": "reload", "image": "image"}},
			"volumes": []any{map[string]any{
				"name":     "etc-selinux",
				"hostPath": map[string]any{"path": "/etc/selinux", "type": "Directory"},
			}},
		}}},
	}

	for _, tc := range []struct {
		name     string
		nodes    []any
		admitted bool
	}{
		{name: "node of the requesting pod", nodes: []any{"node-a"}, admitted: true},
		{name: "other node", nodes: []any{"node-b"}, admitted: false},
		{name: "no node claim", nodes: nil, admitted: false},
		{name: "empty node claim", nodes: []any{}, admitted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.admitted, evaluate(t, env, policy, &request{
				operation: "CREATE",
				kind:      "Job",
				namespace: "security-profiles-operator",
				username:  spodUser,
				nodes:     tc.nodes,
				object:    job,
			}))
		})
	}
}
