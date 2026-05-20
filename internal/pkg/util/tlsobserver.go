/*
Copyright 2020 The Kubernetes Authors.

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

package util

import (
	"context"

	configv1 "github.com/openshift/api/config/v1"
	tlspkg "github.com/openshift/controller-runtime-common/pkg/tls"
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupTLSWatcher sets up a TLS configuration watcher with the controller manager.
// It watches the OpenShift APIServer resource for TLS profile and adherence policy changes
// and triggers graceful shutdown when configuration changes, allowing the operator to restart
// with the new TLS settings.
//
// The onProfileChange callback is called when the TLS profile changes. This should
// typically trigger a graceful shutdown to restart the operator with new TLS settings.
//
// The onAdherencePolicyChange callback is called when the TLS adherence policy changes.
// This should also trigger a graceful shutdown since it affects whether the cluster
// TLS profile should be honored.
func SetupTLSWatcher(
	mgr ctrl.Manager,
	initialProfile configv1.TLSProfileSpec,
	initialAdherencePolicy configv1.TLSAdherencePolicy,
	onProfileChange func(ctx context.Context, oldProfile, newProfile configv1.TLSProfileSpec),
	onAdherencePolicyChange func(ctx context.Context, oldPolicy, newPolicy configv1.TLSAdherencePolicy),
) error {
	log := ctrl.Log.WithName("tls-watcher")

	watcher := &tlspkg.SecurityProfileWatcher{
		Client:                    mgr.GetClient(),
		InitialTLSProfileSpec:     initialProfile,
		InitialTLSAdherencePolicy: initialAdherencePolicy,
		OnProfileChange: func(ctx context.Context, oldProfile, newProfile configv1.TLSProfileSpec) {
			log.Info("TLS profile changed - triggering graceful shutdown for restart",
				"old-min-version", oldProfile.MinTLSVersion,
				"new-min-version", newProfile.MinTLSVersion)

			if onProfileChange != nil {
				onProfileChange(ctx, oldProfile, newProfile)
			}
		},
		OnAdherencePolicyChange: func(ctx context.Context, oldPolicy, newPolicy configv1.TLSAdherencePolicy) {
			log.Info("TLS adherence policy changed - triggering graceful shutdown for restart",
				"old-policy", oldPolicy,
				"new-policy", newPolicy)

			if onAdherencePolicyChange != nil {
				onAdherencePolicyChange(ctx, oldPolicy, newPolicy)
			}
		},
	}

	return watcher.SetupWithManager(mgr)
}
