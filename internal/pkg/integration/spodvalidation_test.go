//go:build integration

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

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

// TestSPODValidation asserts the validation rules of the SPOD CRD in a real
// API server, which also proves that their CEL cost fits the budget.
func TestSPODValidation(t *testing.T) {
	t.Parallel()
	requireEnv(t)

	scheme := runtime.NewScheme()
	require.NoError(t, spodapi.AddToScheme(scheme))

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	trustedRoot := &corev1.ConfigMapKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "trusted-root"},
		Key:                  "trusted_root.json",
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*spodapi.SecurityProfilesOperatorDaemon)
		wantErr string
	}{
		{
			name: "offline without trusted root",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.Security.SignatureVerification = &spodapi.SPODSignatureVerification{
					Offline: new(true),
				}
			},
			wantErr: "offline requires trustedRootConfigMapRef",
		},
		{
			name: "offline with trusted root",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.Security.SignatureVerification = &spodapi.SPODSignatureVerification{
					Offline:                 new(true),
					TrustedRootConfigMapRef: trustedRoot,
				}
			},
		},
		{
			name: "online without trusted root",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.Security.SignatureVerification = &spodapi.SPODSignatureVerification{
					Offline:           new(false),
					AllowedOidcIssuer: "https://issuer.example.com",
				}
			},
		},
		{
			name: "other name",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Name = "other"
			},
			wantErr: "must be named spod",
		},
		{
			name: "generated name",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Name = ""
				spod.GenerateName = "spod-"
			},
			wantErr: "must be named spod",
		},
		{
			name: "empty update strategy",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{}
			},
			wantErr: "daemonUpdateStrategy",
		},
		{
			name: "max unavailable number",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromInt32(1)),
				}
			},
		},
		{
			name: "max unavailable percentage",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromString("100%")),
				}
			},
		},
		{
			name: "max unavailable zero",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromInt32(0)),
				}
			},
			wantErr: "maxUnavailable must be",
		},
		{
			name: "max unavailable zero percent",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromString("0%")),
				}
			},
			wantErr: "maxUnavailable must be",
		},
		{
			name: "max unavailable above 100 percent",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromString("101%")),
				}
			},
			wantErr: "maxUnavailable must be",
		},
		{
			name: "max unavailable without percent sign",
			mutate: func(spod *spodapi.SecurityProfilesOperatorDaemon) {
				spod.Spec.DaemonUpdateStrategy = &spodapi.SPODDaemonUpdateStrategy{
					MaxUnavailable: new(intstr.FromString("1")),
				}
			},
			wantErr: "maxUnavailable must be",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The SPOD has to be named spod, so every case gets its own
			// namespace.
			spod := &spodapi.SecurityProfilesOperatorDaemon{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "spod",
					Namespace: newNamespace(t),
				},
				Spec: spodapi.SPODSpec{
					Webhook: spodapi.SPODWebhookConfig{
						Options: []spodapi.WebhookOptions{{
							Name: "binding.spo.io",
							NamespaceSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{{
									Key:      "kubernetes.io/metadata.name",
									Operator: metav1.LabelSelectorOpNotIn,
									Values:   []string{"kube-system"},
								}},
							},
						}},
					},
				},
			}
			tc.mutate(spod)

			err := c.Create(t.Context(), spod)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.NoError(t, c.Delete(t.Context(), spod))

				return
			}

			require.True(t, apierrors.IsInvalid(err), "unexpected error: %v", err)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
