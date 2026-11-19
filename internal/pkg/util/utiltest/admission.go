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

package utiltest

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResourceRequest is the part of an admission request which the resource
// rules of a ValidatingAdmissionPolicy match.
type ResourceRequest struct {
	Operation admissionregv1.OperationType
	Group     string
	Version   string
	Resource  string
	// Subresource is empty for the main resource.
	Subresource string
}

// RequireOnlyResourceRules asserts that the policy selects its requests by
// the resource rules only, which MatchesResourceRules evaluates, so that the
// tests of the policy cannot match other requests than the API server once
// the policy grows.
func RequireOnlyResourceRules(t *testing.T, policy *admissionregv1.ValidatingAdmissionPolicy) {
	t.Helper()

	constraints := policy.Spec.MatchConstraints
	require.NotNil(t, constraints)
	require.Empty(t, constraints.ExcludeResourceRules)

	for _, selector := range []*metav1.LabelSelector{
		constraints.NamespaceSelector, constraints.ObjectSelector,
	} {
		if selector != nil {
			require.Empty(t, selector.MatchLabels)
			require.Empty(t, selector.MatchExpressions)
		}
	}

	if constraints.MatchPolicy != nil {
		require.Equal(t, admissionregv1.Equivalent, *constraints.MatchPolicy)
	}

	for i := range constraints.ResourceRules {
		rule := &constraints.ResourceRules[i]
		require.Empty(t, rule.ResourceNames)
		require.True(t, rule.Scope == nil || *rule.Scope == admissionregv1.AllScopes,
			"the tests match requests of any scope")
		require.True(t,
			slices.Contains(rule.APIVersions, "*") || slices.Contains(rule.APIVersions, "v1"),
			"the tests match requests of version v1",
		)

		for _, resource := range rule.Resources {
			require.NotContains(t, resource, "*")
		}
	}
}

// MatchesResourceRules returns whether one of the resource rules of the
// policy matches the request like the API server does, for the rules which
// RequireOnlyResourceRules accepts.
func MatchesResourceRules(
	policy *admissionregv1.ValidatingAdmissionPolicy, req *ResourceRequest,
) bool {
	resource := req.Resource
	if req.Subresource != "" {
		resource += "/" + req.Subresource
	}

	matches := func(values []string, value string) bool {
		return slices.Contains(values, value) || slices.Contains(values, "*")
	}

	for i := range policy.Spec.MatchConstraints.ResourceRules {
		rule := &policy.Spec.MatchConstraints.ResourceRules[i]

		operations := make([]string, 0, len(rule.Operations))
		for _, operation := range rule.Operations {
			operations = append(operations, string(operation))
		}

		if matches(rule.APIGroups, req.Group) &&
			matches(rule.APIVersions, req.Version) &&
			matches(operations, string(req.Operation)) &&
			slices.Contains(rule.Resources, resource) {
			return true
		}
	}

	return false
}
