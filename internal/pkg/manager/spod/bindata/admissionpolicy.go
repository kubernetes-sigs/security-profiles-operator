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
	stderrors "errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	admissionregv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// RecordingProfilesPolicyName is the name of the ValidatingAdmissionPolicy and
// its binding which restrict the use of the recording profiles.
const RecordingProfilesPolicyName = "spo-recording-profiles"

// AdmissionPolicies are the ValidatingAdmissionPolicies managed by the
// operator, which enforce rules the webhooks cannot, because they have to
// apply to all namespaces and to the final state of an object.
type AdmissionPolicies struct {
	objects []client.Object
}

// GetAdmissionPolicies returns the policies for the provided namespace
// selector of the recording webhook. A nil selector selects all namespaces.
func GetAdmissionPolicies(recordingNamespaceSelector *metav1.LabelSelector) *AdmissionPolicies {
	recordingEnabled := namespaceSelectorExpression(recordingNamespaceSelector)

	return &AdmissionPolicies{
		objects: []client.Object{
			recordingProfilesPolicy(recordingEnabled),
			policyBinding(RecordingProfilesPolicyName),
		},
	}
}

// IsAdmissionPolicyName returns true if the name is the one of an admission
// policy or binding managed by the operator.
func IsAdmissionPolicyName(name string) bool {
	return name == RecordingProfilesPolicyName
}

// Apply creates the policies and their bindings if they do not exist, or
// restores them if they differ from the desired state, for example because
// they got changed manually. It returns an error matched by IsNotFound if the
// cluster does not serve the ValidatingAdmissionPolicy API.
func (p *AdmissionPolicies) Apply(ctx context.Context, c client.Client) error {
	for _, desired := range p.objects {
		existing, ok := desired.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("copy %T: %w", desired, errNotAnObject)
		}

		if err := c.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
			if !errors.IsNotFound(err) {
				return fmt.Errorf("get %T %s: %w", desired, desired.GetName(), err)
			}

			obj, ok := desired.DeepCopyObject().(client.Object)
			if !ok {
				return fmt.Errorf("copy %T: %w", desired, errNotAnObject)
			}

			// The cache may not know an object which got just created. Its
			// watch event triggers the next reconciliation.
			if err := c.Create(ctx, obj); err != nil && !errors.IsAlreadyExists(err) {
				return fmt.Errorf("create %T %s: %w", obj, obj.GetName(), err)
			}

			continue
		}

		if !restore(desired, existing) {
			continue
		}

		// The update uses the fetched resource version, so it fails on a
		// concurrent change and gets retried by the next reconciliation.
		if err := c.Update(ctx, existing); err != nil {
			return fmt.Errorf("update %T %s: %w", existing, existing.GetName(), err)
		}
	}

	return nil
}

// restore sets the owned fields of the existing object to the desired ones
// and returns true if any of them differed. The spec is owned as a whole, so
// fields added manually get removed. The desired objects carry the defaults
// of the API server, so that defaulted fields do not count as a difference.
func restore(desired, existing client.Object) bool {
	changed := false

	labels := existing.GetLabels()
	for k, v := range desired.GetLabels() {
		if labels[k] != v {
			if labels == nil {
				labels = map[string]string{}
			}

			labels[k] = v
			changed = true
		}
	}

	existing.SetLabels(labels)

	switch d := desired.(type) {
	case *admissionregv1.ValidatingAdmissionPolicy:
		e, ok := existing.(*admissionregv1.ValidatingAdmissionPolicy)
		if ok && !equality.Semantic.DeepEqual(d.Spec, e.Spec) {
			e.Spec = *d.Spec.DeepCopy()
			changed = true
		}
	case *admissionregv1.ValidatingAdmissionPolicyBinding:
		e, ok := existing.(*admissionregv1.ValidatingAdmissionPolicyBinding)
		if ok && !equality.Semantic.DeepEqual(d.Spec, e.Spec) {
			e.Spec = *d.Spec.DeepCopy()
			changed = true
		}
	}

	return changed
}

var errNotAnObject = stderrors.New("not a client.Object")

func policyBinding(name string) *admissionregv1.ValidatingAdmissionPolicyBinding {
	return &admissionregv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{labelApp: config.OperatorName},
		},
		Spec: admissionregv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        name,
			ValidationActions: []admissionregv1.ValidationAction{admissionregv1.Deny},
		},
	}
}

func newPolicy(
	name string,
	rules []admissionregv1.NamedRuleWithOperations,
	variables []admissionregv1.Variable,
	validations []admissionregv1.Validation,
) *admissionregv1.ValidatingAdmissionPolicy {
	return &admissionregv1.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{labelApp: config.OperatorName},
		},
		Spec: admissionregv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: new(admissionregv1.Fail),
			// The selectors and match policy are set to the defaults of the
			// API server, so that the drift detection does not see them.
			MatchConstraints: &admissionregv1.MatchResources{
				ResourceRules:     rules,
				MatchPolicy:       new(admissionregv1.Equivalent),
				NamespaceSelector: &metav1.LabelSelector{},
				ObjectSelector:    &metav1.LabelSelector{},
			},
			Variables:   variables,
			Validations: validations,
		},
	}
}

func namedRule(
	operation admissionregv1.OperationType, group, resource string,
) admissionregv1.NamedRuleWithOperations {
	version := "*"
	if group == "" {
		version = "v1"
	}

	return admissionregv1.NamedRuleWithOperations{
		RuleWithOperations: admissionregv1.RuleWithOperations{
			Operations: []admissionregv1.OperationType{operation},
			Rule: admissionregv1.Rule{
				APIGroups:   []string{group},
				APIVersions: []string{version},
				Resources:   []string{resource},
				Scope:       new(admissionregv1.AllScopes),
			},
		},
	}
}

// recordingProfilesPolicy restricts the use of the profiles which the log
// based recording applies to the recorded containers. The log enricher
// seccomp profile allows every syscall and the SELinux recording type is
// permissive, so any pod referencing them would run effectively unconfined,
// even under the restricted pod security standard, which accepts all
// Localhost profiles. The policy therefore only admits them in namespaces in
// which the recording webhook is active. Namespace labels are usually managed
// by cluster admins, so tenants cannot grant this to themselves.
func recordingProfilesPolicy(recordingEnabled string) *admissionregv1.ValidatingAdmissionPolicy {
	seccompProfile := path.Join(
		config.OperatorProfilesFolder, config.LogEnricherProfile+seccompprofileapi.ExtJSON,
	)
	selinuxType := strconv.Quote(config.SelinuxPermissiveProfile)

	// The kubelet cleans the localhost profile path, so empty and "."
	// segments are ignored for the comparison. The API server rejects ".."
	// segments.
	seccompSegments := make([]string, 0, 2)
	for segment := range strings.SplitSeq(seccompProfile, "/") {
		seccompSegments = append(seccompSegments, strconv.Quote(segment))
	}

	// uses returns an expression which is true if the security context at the
	// provided path references one of the recording profiles.
	uses := func(sc string) string {
		return fmt.Sprintf(
			"has(%[1]s) && ("+
				"(has(%[1]s.seccompProfile) && has(%[1]s.seccompProfile.localhostProfile) && "+
				"%[1]s.seccompProfile.localhostProfile.split('/').filter(s, s != '' && s != '.') == [%[2]s]) || "+
				"(has(%[1]s.seLinuxOptions) && has(%[1]s.seLinuxOptions.type) && "+
				"%[1]s.seLinuxOptions.type == %[3]s))",
			sc, strings.Join(seccompSegments, ", "), selinuxType,
		)
	}

	// Adding ephemeral containers cannot change the other containers, so only
	// the new ephemeral containers are checked. Debugging a pod which got
	// recorded before keeps working after the recording got disabled.
	newEphemeralUses := "has(object.spec.ephemeralContainers) && " +
		"object.spec.ephemeralContainers.exists(c, " +
		"!(oldObject != null && has(oldObject.spec.ephemeralContainers) && " +
		"oldObject.spec.ephemeralContainers.exists(o, o.name == c.name)) && " +
		uses("c.securityContext") + ")"

	podUses := uses("object.spec.securityContext") + " || " +
		"object.spec.containers.exists(c, " + uses("c.securityContext") + ") || " +
		"(has(object.spec.initContainers) && object.spec.initContainers.exists(c, " +
		uses("c.securityContext") + ")) || " +
		"(has(object.spec.ephemeralContainers) && object.spec.ephemeralContainers.exists(c, " +
		uses("c.securityContext") + "))"

	return newPolicy(
		RecordingProfilesPolicyName,
		[]admissionregv1.NamedRuleWithOperations{
			namedRule(admissionregv1.Create, "", "pods"),
			namedRule(admissionregv1.Update, "", "pods/ephemeralcontainers"),
		},
		[]admissionregv1.Variable{
			{
				Name:       "recordingEnabled",
				Expression: recordingEnabled,
			},
			{
				Name: "usesRecordingProfile",
				// The API server omits an empty sub resource from the request.
				Expression: "has(request.subResource) && request.subResource == 'ephemeralcontainers' ? (" +
					newEphemeralUses + ") : (" + podUses + ")",
			},
		},
		[]admissionregv1.Validation{{
			Expression: "variables.recordingEnabled || !variables.usesRecordingProfile",
			Message: fmt.Sprintf(
				"the profile recording seccomp profile %q and SELinux type %s "+
					"can only be used in namespaces with profile recording enabled",
				seccompProfile, selinuxType,
			),
			Reason: new(metav1.StatusReasonForbidden),
		}},
	)
}

// namespaceSelectorExpression converts the label selector into a CEL
// expression over the labels of the namespace of the request. A nil selector
// selects everything, like it does for webhooks.
func namespaceSelectorExpression(selector *metav1.LabelSelector) string {
	if selector == nil {
		return "true"
	}

	const labels = "namespaceObject.metadata.labels"

	// hasLabel returns an expression which is true if the namespace has the
	// label key, guarding against namespaces without any labels.
	hasLabel := func(key string) string {
		return fmt.Sprintf("(has(%s) && %s in %s)", labels, strconv.Quote(key), labels)
	}

	valueIn := func(key string, values []string) string {
		quoted := make([]string, 0, len(values))
		for _, v := range values {
			quoted = append(quoted, strconv.Quote(v))
		}

		return fmt.Sprintf(
			"(%s && %s[%s] in [%s])",
			hasLabel(key), labels, strconv.Quote(key), strings.Join(quoted, ", "),
		)
	}

	terms := []string{}

	for _, key := range slices.Sorted(maps.Keys(selector.MatchLabels)) {
		terms = append(terms, valueIn(key, []string{selector.MatchLabels[key]}))
	}

	for _, req := range selector.MatchExpressions {
		switch req.Operator {
		case metav1.LabelSelectorOpIn:
			terms = append(terms, valueIn(req.Key, req.Values))
		case metav1.LabelSelectorOpNotIn:
			terms = append(terms, "!"+valueIn(req.Key, req.Values))
		case metav1.LabelSelectorOpExists:
			terms = append(terms, hasLabel(req.Key))
		case metav1.LabelSelectorOpDoesNotExist:
			terms = append(terms, "!"+hasLabel(req.Key))
		default:
			// The API server rejects invalid operators in webhook
			// configurations, so the recording webhook matches nothing.
			return "false"
		}
	}

	if len(terms) == 0 {
		return "true"
	}

	return strings.Join(terms, " && ")
}
