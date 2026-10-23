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
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/yaml"
)

// The operator creates the policies which the deployments ship, so the
// embedded copies have to match them.
func TestSpodAdmissionPoliciesMatchDeployment(t *testing.T) {
	t.Parallel()

	names, err := spodPolicyFiles.ReadDir("admissionpolicies")
	require.NoError(t, err)

	deployed, err := filepath.Glob(filepath.Join("..", "..", "..", "..", "..",
		"deploy", "base", "spod_*_policy.yaml"))
	require.NoError(t, err)
	require.Len(t, names, len(deployed))

	for _, entry := range names {
		embedded, err := spodPolicyFiles.ReadFile(path.Join("admissionpolicies", entry.Name()))
		require.NoError(t, err)

		deployment, err := os.ReadFile(filepath.Join(
			"..", "..", "..", "..", "..", "deploy", "base", entry.Name(),
		))
		require.NoError(t, err)
		require.Equal(t, string(deployment), string(embedded),
			"copy deploy/base/%s to admissionpolicies", entry.Name())
	}
}

// The operator reads and updates the policies by name, which its role has to
// allow, see the RBAC markers of the SPOD controller.
func TestSpodAdmissionPoliciesMatchRole(t *testing.T) {
	t.Parallel()

	content, err := os.ReadFile(
		filepath.Join("..", "..", "..", "..", "..", "deploy", "base", "role.yaml"),
	)
	require.NoError(t, err)

	reader := yamlutil.NewYAMLReader(bufio.NewReader(bytes.NewReader(content)))

	var found []string

	for {
		doc, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		role := &rbacv1.ClusterRole{}
		require.NoError(t, yaml.Unmarshal(doc, role))

		if role.Kind != "ClusterRole" || role.Name != "security-profiles-operator" {
			continue
		}

		for _, rule := range role.Rules {
			if slices.Contains(rule.Resources, "validatingadmissionpolicies") &&
				slices.Contains(rule.Resources, "validatingadmissionpolicybindings") &&
				slices.Contains(rule.ResourceNames, SpodAdmissionPolicyNames[0]) {
				require.Empty(t, found, "the names are in a single rule")
				require.ElementsMatch(t, []string{"get", "update"}, rule.Verbs)

				found = rule.ResourceNames
			}
		}
	}

	require.ElementsMatch(t, SpodAdmissionPolicyNames, found)
}

func TestGetSpodAdmissionPolicies(t *testing.T) {
	t.Parallel()

	policies, err := GetSpodAdmissionPolicies("spo")
	require.NoError(t, err)

	policyNames := sets.New[string]()
	bindingNames := sets.New[string]()

	for _, obj := range policies.objects {
		require.NotEmpty(t, obj.GetAnnotations()[spodPolicyHashAnnotation])

		switch o := obj.(type) {
		case *admissionregv1.ValidatingAdmissionPolicy:
			policyNames.Insert(o.Name)
			require.NotEmpty(t, o.Spec.Validations, o.Name)
		case *admissionregv1.ValidatingAdmissionPolicyBinding:
			bindingNames.Insert(o.Name)
			require.Equal(t, o.Name, o.Spec.PolicyName)
		}
	}

	require.ElementsMatch(t, SpodAdmissionPolicyNames, policyNames.UnsortedList())
	require.ElementsMatch(t, SpodAdmissionPolicyNames, bindingNames.UnsortedList())
}

// The policies which the operator creates only select the spod service
// account of the operator namespace, the ones of the deployments the ones of
// all namespaces.
func TestSpodAdmissionPoliciesSelectOperatorNamespace(t *testing.T) {
	t.Parallel()

	hashes := map[string]string{}

	for _, namespace := range []string{"spo", "other"} {
		policies, err := GetSpodAdmissionPolicies(namespace)
		require.NoError(t, err)

		for _, obj := range policies.objects {
			policy, ok := obj.(*admissionregv1.ValidatingAdmissionPolicy)
			if !ok {
				continue
			}

			var conditions []string

			for _, condition := range policy.Spec.MatchConditions {
				if condition.Name == spodServiceAccountCondition {
					conditions = append(conditions, condition.Expression)
				}
			}

			require.Equal(t, []string{
				`request.userInfo.username == "system:serviceaccount:` + namespace + `:spod"`,
			}, conditions, policy.Name)

			hash := policy.Annotations[spodPolicyHashAnnotation]
			require.NotEqual(t, hashes[policy.Name], hash, "the hash covers the namespace")
			hashes[policy.Name] = hash
		}
	}

	// The parsed policies stay the ones of the deployments.
	parsed, err := parseSpodPolicies()
	require.NoError(t, err)

	for _, obj := range parsed {
		if policy, ok := obj.(*admissionregv1.ValidatingAdmissionPolicy); ok {
			for _, condition := range policy.Spec.MatchConditions {
				require.NotContains(
					t,
					condition.Expression,
					"system:serviceaccount:spo:",
					policy.Name,
				)
				require.NotContains(
					t,
					condition.Expression,
					"system:serviceaccount:other:",
					policy.Name,
				)
			}
		}
	}
}

func TestSpodAdmissionPoliciesApply(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, admissionregv1.AddToScheme(scheme))

	// The policies remember when they got applied, so every test gets its
	// own.
	newPolicies := func(t *testing.T) *SpodAdmissionPolicies {
		t.Helper()

		policies, err := GetSpodAdmissionPolicies("spo")
		require.NoError(t, err)

		return policies
	}

	key := client.ObjectKey{Name: SpodAdmissionPolicyNames[0]}

	t.Run("create missing", func(t *testing.T) {
		t.Parallel()

		cl := fake.NewClientBuilder().WithScheme(scheme).Build()
		require.NoError(t, newPolicies(t).Apply(t.Context(), cl, cl))

		list := &admissionregv1.ValidatingAdmissionPolicyList{}
		require.NoError(t, cl.List(t.Context(), list))
		require.Len(t, list.Items, len(SpodAdmissionPolicyNames))

		bindings := &admissionregv1.ValidatingAdmissionPolicyBindingList{}
		require.NoError(t, cl.List(t.Context(), bindings))
		require.Len(t, bindings.Items, len(SpodAdmissionPolicyNames))
	})

	t.Run("keep the ones of the deployment", func(t *testing.T) {
		t.Parallel()

		shipped := &admissionregv1.ValidatingAdmissionPolicy{}
		shipped.Name = key.Name
		shipped.Spec.Validations = []admissionregv1.Validation{{Expression: "true"}}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(shipped).Build()
		require.NoError(t, newPolicies(t).Apply(t.Context(), cl, cl))

		got := &admissionregv1.ValidatingAdmissionPolicy{}
		require.NoError(t, cl.Get(t.Context(), key, got))
		require.Equal(t, shipped.Spec.Validations, got.Spec.Validations)
		require.NotContains(t, got.Annotations, spodPolicyHashAnnotation)
	})

	t.Run("update the ones of an older release", func(t *testing.T) {
		t.Parallel()

		older := &admissionregv1.ValidatingAdmissionPolicy{}
		older.Name = key.Name
		older.Annotations = map[string]string{spodPolicyHashAnnotation: "older"}
		older.Spec.Validations = []admissionregv1.Validation{{Expression: "true"}}

		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(older).Build()
		require.NoError(t, newPolicies(t).Apply(t.Context(), cl, cl))

		got := &admissionregv1.ValidatingAdmissionPolicy{}
		require.NoError(t, cl.Get(t.Context(), key, got))
		require.NotEqual(t, older.Spec.Validations, got.Spec.Validations)
		require.NotEqual(t, "older", got.Annotations[spodPolicyHashAnnotation])
	})

	t.Run("check again only after the resync", func(t *testing.T) {
		t.Parallel()

		gets := 0
		fail := false
		cl := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(
				ctx context.Context, c client.WithWatch, key client.ObjectKey,
				obj client.Object, opts ...client.GetOption,
			) error {
				gets++

				if fail {
					return errTest
				}

				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()

		now := time.Now()
		policies := newPolicies(t)
		policies.now = func() time.Time { return now }

		objects := 2 * len(SpodAdmissionPolicyNames)

		require.NoError(t, policies.Apply(t.Context(), cl, cl))
		require.Equal(t, objects, gets)

		// Deleted policies only get created again after the resync.
		require.NoError(t, cl.Delete(t.Context(), policies.objects[0]))
		require.NoError(t, policies.Apply(t.Context(), cl, cl))
		require.Equal(t, objects, gets)

		now = now.Add(SpodPolicyResync)

		require.NoError(t, policies.Apply(t.Context(), cl, cl))
		require.Equal(t, 2*objects, gets)
		require.NoError(t, cl.Get(t.Context(), client.ObjectKeyFromObject(policies.objects[0]),
			&admissionregv1.ValidatingAdmissionPolicy{}))

		// A failure checks them again on the next reconciliation.
		now = now.Add(SpodPolicyResync)
		fail = true

		require.Error(t, policies.Apply(t.Context(), cl, cl))

		fail = false
		gets = 0

		require.NoError(t, policies.Apply(t.Context(), cl, cl))
		require.Equal(t, objects, gets)
	})
}
