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

package bindata

import (
	"context"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// policy returns the policy with the provided name.
func (p *AdmissionPolicies) policy(
	t *testing.T,
	name string,
) *admissionregv1.ValidatingAdmissionPolicy {
	t.Helper()

	for _, obj := range p.objects {
		if policy, ok := obj.(*admissionregv1.ValidatingAdmissionPolicy); ok &&
			policy.Name == name {
			return policy
		}
	}

	require.FailNow(t, "policy not found", name)

	return nil
}

// evaluatePolicy evaluates the policy like the API server does: the variables
// in order, followed by the validations. It returns whether the object in the
// namespace gets admitted.
func evaluatePolicy(
	t *testing.T,
	policy *admissionregv1.ValidatingAdmissionPolicy,
	obj runtime.Object,
	ns *corev1.Namespace,
) bool {
	t.Helper()

	return evaluatePolicyRequest(t, policy, obj, nil, "", ns)
}

// evaluatePolicyRequest is evaluatePolicy for an update of the provided sub
// resource, for which the old object is set.
func evaluatePolicyRequest(
	t *testing.T,
	policy *admissionregv1.ValidatingAdmissionPolicy,
	obj, oldObj runtime.Object,
	subResource string,
	ns *corev1.Namespace,
) bool {
	t.Helper()

	env, err := cel.NewEnv(
		ext.Strings(),
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
		cel.Variable("namespaceObject", cel.DynType),
		cel.Variable("variables", cel.MapType(cel.StringType, cel.DynType)),
	)
	require.NoError(t, err)

	// The API server omits an empty sub resource from the request, like all
	// empty fields.
	request := map[string]any{}
	if subResource != "" {
		request["subResource"] = subResource
	}

	var oldObject any

	if oldObj != nil {
		oldObject, err = runtime.DefaultUnstructuredConverter.ToUnstructured(oldObj)
		require.NoError(t, err)
	}

	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	require.NoError(t, err)

	// Cluster scoped objects have no namespace object.
	var namespaceObject map[string]any

	if ns != nil {
		namespaceObject, err = runtime.DefaultUnstructuredConverter.ToUnstructured(ns)
		require.NoError(t, err)
	}

	variables := map[string]any{}
	eval := func(expression string) any {
		ast, issues := env.Compile(expression)
		require.NoError(t, issues.Err(), expression)

		prg, err := env.Program(ast)
		require.NoError(t, err)

		out, _, err := prg.Eval(map[string]any{
			"object":          object,
			"oldObject":       oldObject,
			"request":         request,
			"namespaceObject": namespaceObject,
			"variables":       variables,
		})
		require.NoError(t, err, expression)

		return out.Value()
	}

	for _, v := range policy.Spec.Variables {
		variables[v.Name] = eval(v.Expression)
	}

	for _, v := range policy.Spec.Validations {
		admitted, ok := eval(v.Expression).(bool)
		require.True(t, ok)

		if !admitted {
			return false
		}
	}

	return true
}

func TestRecordingProfilesPolicy(t *testing.T) {
	t.Parallel()

	trace := "operator/log-enricher-trace.json"
	other := "operator/other.json"

	seccomp := func(profile string) *corev1.SeccompProfile {
		return &corev1.SeccompProfile{
			Type:             corev1.SeccompProfileTypeLocalhost,
			LocalhostProfile: &profile,
		}
	}

	labeled := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "labeled",
		Labels: map[string]string{EnableRecordingLabel: "true"},
	}}
	unlabeled := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unlabeled"}}
	otherLabels := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name:   "other",
		Labels: map[string]string{"team": "a"},
	}}

	for _, tc := range []struct {
		name     string
		selector *metav1.LabelSelector
		pod      corev1.PodSpec
		ns       *corev1.Namespace
		admitted bool
	}{
		{
			name:     "no profile",
			selector: requireLabel(EnableRecordingLabel),
			pod:      corev1.PodSpec{Containers: []corev1.Container{{Name: "c"}}},
			ns:       unlabeled,
			admitted: true,
		},
		{
			name:     "other profile",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(other)},
			}}},
			ns:       unlabeled,
			admitted: true,
		},
		{
			name:     "container seccomp in namespace without recording",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns: unlabeled,
		},
		{
			name:     "container seccomp in namespace with other labels",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns: otherLabels,
		},
		{
			name:     "container seccomp in namespace with recording",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns:       labeled,
			admitted: true,
		},
		{
			name:     "container seccomp with an empty segment",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp("operator//log-enricher-trace.json")},
			}}},
			ns: unlabeled,
		},
		{
			name:     "container seccomp with a dot segment",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp("./operator/./log-enricher-trace.json")},
			}}},
			ns: unlabeled,
		},
		{
			name:     "container seccomp with a similar name",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp("operator/log-enricher-trace.json.bak")},
			}}},
			ns:       unlabeled,
			admitted: true,
		},
		{
			name:     "pod seccomp",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{SeccompProfile: seccomp(trace)},
				Containers:      []corev1.Container{{Name: "c"}},
			},
			ns: unlabeled,
		},
		{
			name:     "pod selinux",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					SELinuxOptions: &corev1.SELinuxOptions{Type: "selinuxrecording.process"},
				},
				Containers: []corev1.Container{{Name: "c"}},
			},
			ns: unlabeled,
		},
		{
			name:     "init container selinux",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{
				InitContainers: []corev1.Container{{
					Name: "i",
					SecurityContext: &corev1.SecurityContext{
						SELinuxOptions: &corev1.SELinuxOptions{Type: "selinuxrecording.process"},
					},
				}},
				Containers: []corev1.Container{{Name: "c"}},
			},
			ns: unlabeled,
		},
		{
			name:     "ephemeral container seccomp",
			selector: requireLabel(EnableRecordingLabel),
			pod: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "c"}},
				EphemeralContainers: []corev1.EphemeralContainer{{
					EphemeralContainerCommon: corev1.EphemeralContainerCommon{
						Name:            "e",
						SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
					},
				}},
			},
			ns: unlabeled,
		},
		{
			name:     "all namespaces recorded",
			selector: nil,
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns:       unlabeled,
			admitted: true,
		},
		{
			name: "custom selector matching",
			selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"team": "a"},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"prod"}},
					{Key: "legacy", Operator: metav1.LabelSelectorOpDoesNotExist},
				},
			},
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns:       otherLabels,
			admitted: true,
		},
		{
			name: "custom selector not matching",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"b", "c"}},
				},
			},
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns: otherLabels,
		},
		{
			name: "invalid selector",
			selector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "team", Operator: "Invalid"}},
			},
			pod: corev1.PodSpec{Containers: []corev1.Container{{
				Name:            "c",
				SecurityContext: &corev1.SecurityContext{SeccompProfile: seccomp(trace)},
			}}},
			ns: otherLabels,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policy := GetAdmissionPolicies(tc.selector).policy(t, RecordingProfilesPolicyName)
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod"}, Spec: tc.pod}

			require.Equal(t, tc.admitted, evaluatePolicy(t, policy, pod, tc.ns))
		})
	}
}

func TestAdmissionPoliciesApply(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregv1.AddToScheme(scheme))

	t.Run("create and update", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		require.NoError(t, GetAdmissionPolicies(nil).Apply(t.Context(), cl))

		got := &admissionregv1.ValidatingAdmissionPolicy{}
		key := client.ObjectKey{Name: RecordingProfilesPolicyName}
		require.NoError(t, cl.Get(t.Context(), key, got))
		require.Equal(t, "true", got.Spec.Variables[0].Expression)

		policies := GetAdmissionPolicies(requireLabel(EnableRecordingLabel))
		require.NoError(t, policies.Apply(t.Context(), cl))
		require.NoError(t, cl.Get(t.Context(), key, got))
		require.NotEqual(t, "true", got.Spec.Variables[0].Expression)

		binding := &admissionregv1.ValidatingAdmissionPolicyBinding{}
		require.NoError(t, cl.Get(t.Context(), key, binding))
		require.Equal(t, RecordingProfilesPolicyName, binding.Spec.PolicyName)
	})

	t.Run("restore changed and deleted objects", func(t *testing.T) {
		t.Parallel()

		writes := 0
		cl := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption,
			) error {
				writes++

				return c.Create(ctx, obj, opts...)
			},
			Update: func(
				ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption,
			) error {
				writes++

				return c.Update(ctx, obj, opts...)
			},
		}).Build()

		policies := GetAdmissionPolicies(nil)
		require.NoError(t, policies.Apply(t.Context(), cl))
		require.Equal(t, 2, writes)

		// Nothing to do if the objects are unchanged.
		require.NoError(t, policies.Apply(t.Context(), cl))
		require.Equal(t, 2, writes)

		key := client.ObjectKey{Name: RecordingProfilesPolicyName}
		got := &admissionregv1.ValidatingAdmissionPolicy{}
		require.NoError(t, cl.Get(t.Context(), key, got))
		got.Spec.Validations = nil
		// Added fields weaken the policy as well, so they have to be removed.
		got.Spec.MatchConditions = []admissionregv1.MatchCondition{
			{Name: "never", Expression: "false"},
		}
		got.Labels["other"] = "label"
		require.NoError(t, cl.Update(t.Context(), got))

		binding := &admissionregv1.ValidatingAdmissionPolicyBinding{}
		require.NoError(t, cl.Get(t.Context(), key, binding))
		binding.Spec.MatchResources = &admissionregv1.MatchResources{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"never": "true"},
			},
		}
		require.NoError(t, cl.Update(t.Context(), binding))

		writes = 0

		require.NoError(t, policies.Apply(t.Context(), cl))
		require.Equal(t, 2, writes)

		require.NoError(t, cl.Get(t.Context(), key, got))
		require.NotEmpty(t, got.Spec.Validations)
		require.Empty(t, got.Spec.MatchConditions)
		require.Equal(t, "label", got.Labels["other"], "foreign labels are kept")

		require.NoError(t, cl.Get(t.Context(), key, binding))
		require.Nil(t, binding.Spec.MatchResources)

		require.NoError(t, cl.Delete(t.Context(), binding))
		require.NoError(t, policies.Apply(t.Context(), cl))
		require.NoError(t, cl.Get(t.Context(), key, binding))
	})

	// The API server defaults fields of the policy. The desired policy already
	// carries them, so that they do not cause an update on every
	// reconciliation.
	t.Run("server defaults are no difference", func(t *testing.T) {
		t.Parallel()

		policy := GetAdmissionPolicies(nil).policy(t, RecordingProfilesPolicyName)
		constraints := policy.Spec.MatchConstraints

		require.Equal(t, admissionregv1.Fail, *policy.Spec.FailurePolicy)
		require.Equal(t, admissionregv1.Equivalent, *constraints.MatchPolicy)
		require.Equal(t, &metav1.LabelSelector{}, constraints.NamespaceSelector)
		require.Equal(t, &metav1.LabelSelector{}, constraints.ObjectSelector)

		for _, rule := range constraints.ResourceRules {
			require.Equal(t, admissionregv1.AllScopes, *rule.Scope)
		}

		// Nil and empty lists are equal, like after a round trip through the
		// API server.
		existing := policy.DeepCopy()
		existing.Spec.MatchConditions = []admissionregv1.MatchCondition{}
		existing.Spec.AuditAnnotations = []admissionregv1.AuditAnnotation{}
		require.False(t, restore(policy, existing))
	})

	t.Run("api not served", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				return k8serrors.NewNotFound(schema.GroupResource{}, "")
			},
		}).Build()

		require.True(t, IsNotFound(GetAdmissionPolicies(nil).Apply(t.Context(), cl)))
	})
}

// Adding an ephemeral container to a pod which got recorded before has to keep
// working after the recording got disabled for the namespace.
func TestRecordingProfilesPolicyEphemeralContainers(t *testing.T) {
	t.Parallel()

	policy := GetAdmissionPolicies(requireLabel(EnableRecordingLabel)).
		policy(t, RecordingProfilesPolicyName)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "unlabeled"}}

	trace := "operator/log-enricher-trace.json"
	traced := &corev1.SecurityContext{SeccompProfile: &corev1.SeccompProfile{
		Type:             corev1.SeccompProfileTypeLocalhost,
		LocalhostProfile: &trace,
	}}
	ephemeral := func(name string, sc *corev1.SecurityContext) corev1.EphemeralContainer {
		return corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name: name, SecurityContext: sc,
		}}
	}

	oldPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod"},
		Spec: corev1.PodSpec{
			Containers:          []corev1.Container{{Name: "c", SecurityContext: traced}},
			EphemeralContainers: []corev1.EphemeralContainer{ephemeral("old", traced)},
		},
	}

	debugged := oldPod.DeepCopy()
	debugged.Spec.EphemeralContainers = append(
		debugged.Spec.EphemeralContainers, ephemeral("debug", nil),
	)
	require.True(t, evaluatePolicyRequest(
		t, policy, debugged, oldPod, "ephemeralcontainers", ns,
	))

	escalated := oldPod.DeepCopy()
	escalated.Spec.EphemeralContainers = append(
		escalated.Spec.EphemeralContainers, ephemeral("debug", traced),
	)
	require.False(t, evaluatePolicyRequest(
		t, policy, escalated, oldPod, "ephemeralcontainers", ns,
	))
}
