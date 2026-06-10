/*
Copyright 2025 The Kubernetes Authors.

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

package v1alpha1

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/conversion"

	spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
)

var (
	stateToV1 = map[SPODState]spodv1.SPODState{
		"":                spodv1.SPODStatePending,
		SPODStatePending:  spodv1.SPODStatePending,
		SPODStateCreating: spodv1.SPODStateCreating,
		SPODStateUpdating: spodv1.SPODStateUpdating,
		SPODStateRunning:  spodv1.SPODStateRunning,
		SPODStateError:    spodv1.SPODStateError,
	}
	stateFromV1 = map[spodv1.SPODState]SPODState{
		"":                       SPODStatePending,
		spodv1.SPODStatePending:  SPODStatePending,
		spodv1.SPODStateCreating: SPODStateCreating,
		spodv1.SPODStateUpdating: SPODStateUpdating,
		spodv1.SPODStateRunning:  SPODStateRunning,
		spodv1.SPODStateError:    SPODStateError,
	}
	enricherSourceToV1 = map[string]spodv1.LogEnricherSource{
		"":       spodv1.LogEnricherSourceAuditd,
		"auditd": spodv1.LogEnricherSourceAuditd,
		"bpf":    spodv1.LogEnricherSourceBpf,
	}
	enricherSourceFromV1 = map[spodv1.LogEnricherSource]string{
		"":                             "auditd",
		spodv1.LogEnricherSourceAuditd: "auditd",
		spodv1.LogEnricherSourceBpf:    "bpf",
	}
)

func (src *SecurityProfilesOperatorDaemon) ConvertTo(dstRaw conversion.Hub) error {
	dst, ok := dstRaw.(*spodv1.SecurityProfilesOperatorDaemon)
	if !ok {
		return fmt.Errorf("expected *spodv1.SecurityProfilesOperatorDaemon, got %T", dstRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.Verbosity = src.Spec.Verbosity
	dst.Spec.EnableProfiling = src.Spec.EnableProfiling
	dst.Spec.EnableMemoryOptimization = src.Spec.EnableMemoryOptimization
	dst.Spec.EnableAppArmor = src.Spec.EnableAppArmor
	dst.Spec.HostProcVolumePath = src.Spec.HostProcVolumePath
	dst.Spec.ImagePullSecrets = src.Spec.ImagePullSecrets
	dst.Spec.DaemonResourceRequirements = src.Spec.DaemonResourceRequirements

	// Selinux
	dst.Spec.Selinux.Enable = src.Spec.Selinux.Enable
	dst.Spec.Selinux.EnableRawSelinuxProfiles = src.Spec.Selinux.EnableRawSelinuxProfiles
	dst.Spec.Selinux.TypeTag = src.Spec.Selinux.TypeTag
	dst.Spec.Selinux.Options.AllowedSystemProfiles = src.Spec.Selinux.Options.AllowedSystemProfiles

	// Enricher
	dst.Spec.Enricher.EnableLogEnricher = src.Spec.Enricher.EnableLogEnricher
	dst.Spec.Enricher.LogEnricherFilters = src.Spec.Enricher.LogEnricherFilters
	dst.Spec.Enricher.LogEnricherSource = enricherSourceToV1[src.Spec.Enricher.LogEnricherSource]
	dst.Spec.Enricher.EnableJsonEnricher = src.Spec.Enricher.EnableJsonEnricher
	dst.Spec.Enricher.JsonEnricherFilters = src.Spec.Enricher.JsonEnricherFilters
	dst.Spec.Enricher.EnableBpfRecorder = src.Spec.Enricher.EnableBpfRecorder

	if src.Spec.Enricher.JsonEnricherOptions != nil {
		dst.Spec.Enricher.JsonEnricherOptions = &spodv1.JsonEnricherOptions{
			AuditLogIntervalSeconds: src.Spec.Enricher.JsonEnricherOptions.AuditLogIntervalSeconds,
			AuditLogPath:            src.Spec.Enricher.JsonEnricherOptions.AuditLogPath,
			AuditLogMaxSize:         src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxSize,
			AuditLogMaxBackups:      src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxBackups,
			AuditLogMaxAge:          src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxAge,
		}
	}

	// Webhook
	dst.Spec.Webhook.StaticConfig = src.Spec.Webhook.StaticConfig
	dst.Spec.Webhook.Options = make([]spodv1.WebhookOptions, len(src.Spec.Webhook.Options))

	for i, o := range src.Spec.Webhook.Options {
		dst.Spec.Webhook.Options[i] = spodv1.WebhookOptions{
			Name:              o.Name,
			FailurePolicy:     o.FailurePolicy,
			NamespaceSelector: o.NamespaceSelector,
			ObjectSelector:    o.ObjectSelector,
		}
	}

	// Scheduling
	dst.Spec.Scheduling.Tolerations = src.Spec.Scheduling.Tolerations
	dst.Spec.Scheduling.Affinity = src.Spec.Scheduling.Affinity
	dst.Spec.Scheduling.PriorityClassName = src.Spec.Scheduling.PriorityClassName

	// Security
	dst.Spec.Security.AllowedSyscalls = src.Spec.Security.AllowedSyscalls
	dst.Spec.Security.AllowedSeccompActions = src.Spec.Security.AllowedSeccompActions
	dst.Spec.Security.DisableOCIArtifactSignatureVerification = src.Spec.Security.DisableOCIArtifactSignatureVerification

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.State = stateToV1[src.Status.State]

	return nil
}

func (dst *SecurityProfilesOperatorDaemon) ConvertFrom(srcRaw conversion.Hub) error {
	src, ok := srcRaw.(*spodv1.SecurityProfilesOperatorDaemon)
	if !ok {
		return fmt.Errorf("expected *spodv1.SecurityProfilesOperatorDaemon, got %T", srcRaw)
	}

	dst.ObjectMeta = src.ObjectMeta

	// Spec
	dst.Spec.Verbosity = src.Spec.Verbosity
	dst.Spec.EnableProfiling = src.Spec.EnableProfiling
	dst.Spec.EnableMemoryOptimization = src.Spec.EnableMemoryOptimization
	dst.Spec.EnableAppArmor = src.Spec.EnableAppArmor
	dst.Spec.HostProcVolumePath = src.Spec.HostProcVolumePath
	dst.Spec.ImagePullSecrets = src.Spec.ImagePullSecrets
	dst.Spec.DaemonResourceRequirements = src.Spec.DaemonResourceRequirements

	// Selinux
	dst.Spec.Selinux.Enable = src.Spec.Selinux.Enable
	dst.Spec.Selinux.EnableRawSelinuxProfiles = src.Spec.Selinux.EnableRawSelinuxProfiles
	dst.Spec.Selinux.TypeTag = src.Spec.Selinux.TypeTag
	dst.Spec.Selinux.Options.AllowedSystemProfiles = src.Spec.Selinux.Options.AllowedSystemProfiles

	// Enricher
	dst.Spec.Enricher.EnableLogEnricher = src.Spec.Enricher.EnableLogEnricher
	dst.Spec.Enricher.LogEnricherFilters = src.Spec.Enricher.LogEnricherFilters
	dst.Spec.Enricher.LogEnricherSource = enricherSourceFromV1[src.Spec.Enricher.LogEnricherSource]
	dst.Spec.Enricher.EnableJsonEnricher = src.Spec.Enricher.EnableJsonEnricher
	dst.Spec.Enricher.JsonEnricherFilters = src.Spec.Enricher.JsonEnricherFilters
	dst.Spec.Enricher.EnableBpfRecorder = src.Spec.Enricher.EnableBpfRecorder

	if src.Spec.Enricher.JsonEnricherOptions != nil {
		dst.Spec.Enricher.JsonEnricherOptions = &JsonEnricherOptions{
			AuditLogIntervalSeconds: src.Spec.Enricher.JsonEnricherOptions.AuditLogIntervalSeconds,
			AuditLogPath:            src.Spec.Enricher.JsonEnricherOptions.AuditLogPath,
			AuditLogMaxSize:         src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxSize,
			AuditLogMaxBackups:      src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxBackups,
			AuditLogMaxAge:          src.Spec.Enricher.JsonEnricherOptions.AuditLogMaxAge,
		}
	}

	// Webhook
	dst.Spec.Webhook.StaticConfig = src.Spec.Webhook.StaticConfig
	dst.Spec.Webhook.Options = make([]WebhookOptions, len(src.Spec.Webhook.Options))

	for i, o := range src.Spec.Webhook.Options {
		dst.Spec.Webhook.Options[i] = WebhookOptions{
			Name:              o.Name,
			FailurePolicy:     o.FailurePolicy,
			NamespaceSelector: o.NamespaceSelector,
			ObjectSelector:    o.ObjectSelector,
		}
	}

	// Scheduling
	dst.Spec.Scheduling.Tolerations = src.Spec.Scheduling.Tolerations
	dst.Spec.Scheduling.Affinity = src.Spec.Scheduling.Affinity
	dst.Spec.Scheduling.PriorityClassName = src.Spec.Scheduling.PriorityClassName

	// Security
	dst.Spec.Security.AllowedSyscalls = src.Spec.Security.AllowedSyscalls
	dst.Spec.Security.AllowedSeccompActions = src.Spec.Security.AllowedSeccompActions
	dst.Spec.Security.DisableOCIArtifactSignatureVerification = src.Spec.Security.DisableOCIArtifactSignatureVerification

	// Status
	dst.Status.ConditionedStatus = src.Status.ConditionedStatus
	dst.Status.State = stateFromV1[src.Status.State]

	return nil
}
