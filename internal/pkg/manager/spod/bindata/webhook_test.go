/*
Copyright 2023 The Kubernetes Authors.

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
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testLabel = "test"

func TestNamespaceSelectorUnequalForLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		existing, configured *metav1.LabelSelector
		expected             bool
	}{
		{
			name:       "label not available in both selectors",
			existing:   &metav1.LabelSelector{},
			configured: &metav1.LabelSelector{},
			expected:   false,
		},
		{
			name: "label requirements are equal",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			expected: false,
		},
		{
			name: "label requirements are not equal in value",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"foo"},
				},
			}},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			expected: true,
		},
		{
			name:     "label requirements are not equal (existing does not have the expression)",
			existing: &metav1.LabelSelector{},
			configured: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			expected: true,
		},
		{
			name: "label requirements are not equal (configured does not have the expression)",
			existing: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      testLabel,
					Operator: metav1.LabelSelectorOpExists,
					Values:   []string{"bar"},
				},
			}},
			configured: &metav1.LabelSelector{},
			expected:   true,
		},
	} {
		existing := tc.existing
		configured := tc.configured
		expected := tc.expected

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := namespaceSelectorUnequalForLabel(testLabel, existing, configured)
			assert.Equal(t, expected, res)
		})
	}
}

func TestWebhook_NeedsUpdate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name                 string
		existing, configured *admissionregv1.MutatingWebhook
		expected             bool
	}{
		{
			name:       "label not available in both selectors",
			existing:   &admissionregv1.MutatingWebhook{},
			configured: &admissionregv1.MutatingWebhook{},
			expected:   false,
		},
		{
			name: "Some content in object select and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name: "foo",
				ObjectSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      testLabel,
							Operator: metav1.LabelSelectorOpExists,
							Values:   []string{"val"},
						},
					},
				},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			name: "Empty existing and nil. Required to handle defaults",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: nil,
			},
			expected: false,
		},
		{
			name: "Nil existing and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:           "foo",
				ObjectSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			name: "Nil existing and empty",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: nil,
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: &metav1.LabelSelector{},
			},
			expected: true,
		},
		{
			name: "existing empty and nil",
			existing: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: &metav1.LabelSelector{},
			},
			configured: &admissionregv1.MutatingWebhook{
				Name:              "foo",
				NamespaceSelector: nil,
			},
			expected: false,
		},
	} {
		existing := tc.existing
		configured := tc.configured
		expected := tc.expected
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := Webhook{
				log: logr.Discard(),
				config: &admissionregv1.MutatingWebhookConfiguration{
					Webhooks: []admissionregv1.MutatingWebhook{
						*configured,
					},
				},
			}
			requireUpdate := w.webhookNeedsUpdate(existing, 0)
			assert.Equal(t, expected, requireUpdate)
		})
	}
}

func TestWebhook_getWebhookConfig(t *testing.T) {
	t.Parallel()

	webhookConfig := getWebhookConfig(false)
	require.Len(t, webhookConfig.Webhooks, 2)

	webhookConfig = getWebhookConfig(true)
	require.Len(t, webhookConfig.Webhooks, 4)
}
