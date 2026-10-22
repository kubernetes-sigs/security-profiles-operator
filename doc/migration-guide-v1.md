# Migration Guide: API Graduation to v1

<!-- toc -->
- [API version changes](#api-version-changes)
- [Enum value changes](#enum-value-changes)
- [Field changes from 0.10.x](#field-changes-from-010x)
- [Removal of the old API versions](#removal-of-the-old-api-versions)
- [Upgrade path](#upgrade-path)
- [Recommended actions](#recommended-actions)
- [Examples](#examples)
  - [ProfileRecording](#profilerecording)
- [Go API consumers](#go-api-consumers)
  - [Import paths](#import-paths)
  - [Struct compatibility](#struct-compatibility)
  - [Enum constants](#enum-constants)
  - [Registering the v1 scheme](#registering-the-v1-scheme)
<!-- /toc -->

Security Profiles Operator (SPO) 1.0.0 graduates all CRD APIs from alpha/beta to v1. SPO 1.1.0 removed the old API versions. This document covers what changed, how to upgrade, and what you should update. For general installation and usage instructions, see the [documentation](README.md).

## API version changes

All SPO custom resources move to `security-profiles-operator.x-k8s.io/v1`:

| CRD | Previous version(s) | New version |
|-----|---------------------|-------------|
| SeccompProfile | v1beta1 | v1 |
| SelinuxProfile | v1alpha2 | v1 |
| RawSelinuxProfile | v1alpha2 | v1 |
| AppArmorProfile | v1alpha1 | v1 |
| ProfileRecording | v1alpha1 | v1 |
| ProfileBinding | v1alpha1 | v1 |
| SecurityProfilesOperatorDaemon (SPOD) | v1alpha1 | v1 |
| SecurityProfileNodeStatus | v1alpha1 | v1 |

## Enum value changes

Several enum fields changed from uppercase/lowercase to PascalCase in v1:

| CRD | Field | Old value | New value |
|-----|-------|-----------|-----------|
| ProfileRecording | `spec.recorder` | `logs` | `Logs` |
| ProfileRecording | `spec.recorder` | `bpf` | `Bpf` |
| ProfileRecording | `spec.mergeStrategy` | `none` | `None` |
| ProfileRecording | `spec.mergeStrategy` | `containers` | `Containers` |
| SPOD | `status.state` | `PENDING` | `Pending` |
| SPOD | `status.state` | `CREATING` | `Creating` |
| SPOD | `status.state` | `UPDATING` | `Updating` |
| SPOD | `status.state` | `RUNNING` | `Running` |
| SPOD | `status.state` | `ERROR` | `Error` |
| SPOD | `spec.enricher.logEnricherSource` | `auditd` | `Auditd` |
| SPOD | `spec.enricher.logEnricherSource` | `bpf` | `Bpf` |

## Field changes from 0.10.x

SPO 1.0.0 also renamed and moved fields of the old API versions, so a
manifest written for 0.10.x needs these changes in addition to the new
`apiVersion` and enum values:

| CRD | Field in 0.10.x | Field in 1.0.0 and later |
|-----|-----------------|--------------------------|
| AppArmorProfile | `spec.complainMode: true` | `spec.mode: Complain` |
| SelinuxProfile | `spec.permissive: true` | `spec.mode: Permissive` |
| SPOD | `spec.enableSelinux` | `spec.selinux.enable` |
| SPOD | `spec.selinuxTypeTag` | `spec.selinux.typeTag` |
| SPOD | `spec.selinuxOptions` | `spec.selinux.options` |
| SPOD | `spec.enableLogEnricher` | `spec.enricher.enableLogEnricher` |
| SPOD | `spec.logEnricherFilters` | `spec.enricher.logEnricherFilters` |
| SPOD | `spec.logEnricherSource` | `spec.enricher.logEnricherSource` |
| SPOD | `spec.enableJsonEnricher` | `spec.enricher.enableJsonEnricher` |
| SPOD | `spec.jsonEnricherFilters` | `spec.enricher.jsonEnricherFilters` |
| SPOD | `spec.jsonEnricherOptions` | `spec.enricher.jsonEnricherOptions` |
| SPOD | `spec.enableBpfRecorder` | `spec.enricher.enableBpfRecorder` |
| SPOD | `spec.staticWebhookConfig` | `spec.webhook.staticConfig` |
| SPOD | `spec.webhookOptions` | `spec.webhook.options` |
| SPOD | `spec.tolerations` | `spec.scheduling.tolerations` |
| SPOD | `spec.affinity` | `spec.scheduling.affinity` |
| SPOD | `spec.priorityClassName` | `spec.scheduling.priorityClassName` |
| SPOD | `spec.allowedSyscalls` | `spec.security.allowedSyscalls` |
| SPOD | `spec.allowedSeccompActions` | `spec.security.allowedSeccompActions` |
| SPOD | `spec.disableOciArtifactSignatureVerification` | `spec.security.disableOciArtifactSignatureVerification` |

The CRDs of 1.0.0 and later do not know the old field names. `kubectl apply`
validates the fields strictly by default, so applying a manifest written for
0.10.x fails with an unknown field error. Objects stored before the upgrade,
and objects written by clients which do not request strict field validation,
lose the old fields silently instead: an AppArmorProfile with
`complainMode: true` or a SelinuxProfile with `permissive: true` gets
enforced, and a SPOD loses the settings of the old fields. A lost
`allowedSyscalls` lifts the restriction of the system calls which seccomp
profiles may allow.

Since 1.0.x drops these fields, export the affected objects before the
upgrade, and set the fields under their new names after it:

```bash
kubectl get apparmorprofiles,selinuxprofiles -A -o yaml >profiles-0.10.yaml
kubectl get spod -A -o yaml >spod-0.10.yaml
```

## Removal of the old API versions

SPO 1.0.x serves the old API versions (`v1alpha1`, `v1alpha2`, `v1beta1`)
next to v1 and translates between them using conversion webhooks. v1 is the
storage version starting with 1.0.0.

SPO 1.1.0 removed the old API versions and the conversion webhooks. All CRDs
serve only v1, which means:

- **Old manifests no longer work.** Applying resources with a `v1alpha1`,
  `v1alpha2` or `v1beta1` `apiVersion` fails. Manifests have to use
  `security-profiles-operator.x-k8s.io/v1` and the PascalCase enum values.
- **Old API versions are no longer served.** `kubectl get` and API clients
  have to use v1.
- **Direct upgrades from pre-1.0 releases are not supported.** Upgrade to
  1.0.x first, so that the conversion webhooks are available while the stored
  objects are migrated to v1. The `olm.skipRange` of the OLM bundle therefore
  starts at `>=1.0.0`.

## Upgrade path

1. **Upgrade to 1.0.x.** Install the latest 1.0.x release and wait for the
   operator and the daemon to become ready. Coming from 0.10.x, export the
   objects with renamed fields before the upgrade and set the fields under
   their new names after it, see [field changes](#field-changes-from-010x).

2. **Migrate the stored objects to v1.** Objects written before the upgrade
   to 1.0.x stay stored in their old API version until they are written again.
   Rewrite them while the 1.0.x conversion webhooks are still available, for
   example:
   ```bash
   for crd in seccompprofiles selinuxprofiles rawselinuxprofiles \
     apparmorprofiles profilerecordings profilebindings \
     securityprofilesoperatordaemons securityprofilenodestatuses; do
     kubectl get "$crd.security-profiles-operator.x-k8s.io" -A -o json |
       kubectl replace -f -
   done
   ```
   `kubectl replace` reports an error for resource types without any objects,
   which can be ignored. Rerun the loop if it reports conflicts, which occur
   when the operator updates an object at the same time.

   Then remove the old versions from the stored versions of each CRD:
   ```bash
   for crd in seccompprofiles selinuxprofiles rawselinuxprofiles \
     apparmorprofiles profilerecordings profilebindings \
     securityprofilesoperatordaemons securityprofilenodestatuses; do
     kubectl patch crd "$crd.security-profiles-operator.x-k8s.io" \
       --subresource=status --type=merge -p '{"status":{"storedVersions":["v1"]}}'
   done
   ```
   The Kubernetes API server rejects CRD updates which remove a version that is
   still listed in `status.storedVersions`, so this step is required before
   installing 1.1.x.

3. **Update your manifests and clients to v1** (see
   [Recommended actions](#recommended-actions)).

4. **Upgrade to 1.1.x.** Helm installs the CRDs from the chart's `crds`
   directory only on the first install and never updates them, so a
   `helm upgrade` keeps the 1.0.x CRDs. They still serve the old API
   versions and point to the conversion webhook which 1.1.x removed. Apply
   the CRDs of the new release before running `helm upgrade`, where
   `VERSION` is the release version to upgrade to, for example `1.1.0`:
   ```bash
   kubectl apply --server-side --force-conflicts -f \
     "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/helm/crds/crds.yaml"
   ```
   The manifest and OLM installations update the CRDs on their own.

## Recommended actions

Update everything that references the SPO APIs to v1:

1. **Update YAML manifests.** Change `apiVersion` from
   `security-profiles-operator.x-k8s.io/v1alpha1` (or `v1alpha2`, `v1beta1`)
   to `security-profiles-operator.x-k8s.io/v1`.

2. **Update enum values in manifests.** If you reference enum fields in
   manifests or scripts, update them to PascalCase (see table above).

3. **Update renamed fields.** Manifests written for 0.10.x have to use the new
   field names of the [field changes](#field-changes-from-010x) table.

4. **Update Go client imports.** If you consume the SPO API types in Go code,
   update imports from `api/*/v1alpha1` to `api/*/v1`. For example:
   ```go
   // Before
   import profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
   // After
   import profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
   ```

5. **Update scripts that parse enum strings.** If automation or monitoring
   checks for specific enum string values (e.g., checking SPOD status for
   `"RUNNING"`), update those checks to use PascalCase (`"Running"`).

## Examples

### ProfileRecording

Before (v1alpha1):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: my-recording
spec:
  kind: SeccompProfile
  recorder: logs
  mergeStrategy: none
  podSelector:
    matchLabels:
      app: my-app
```

After (v1):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: my-recording
spec:
  kind: SeccompProfile
  recorder: Logs
  mergeStrategy: None
  podSelector:
    matchLabels:
      app: my-app
```

For SeccompProfile, RawSelinuxProfile and ProfileBinding, only the
`apiVersion` line needs updating. SelinuxProfile, AppArmorProfile and SPOD
manifests written for 0.10.x also need the
[field changes](#field-changes-from-010x).

## Go API consumers

If you import the SPO API types in Go code (e.g., for a custom controller or
CLI tool), this section covers what to change.

### Import paths

Update all imports from the old API version packages to v1:

| CRD | Old import | New import |
|-----|-----------|------------|
| SeccompProfile | `api/seccompprofile/v1beta1` | `api/seccompprofile/v1` |
| SelinuxProfile, RawSelinuxProfile | `api/selinuxprofile/v1alpha2` | `api/selinuxprofile/v1` |
| AppArmorProfile | `api/apparmorprofile/v1alpha1` | `api/apparmorprofile/v1` |
| ProfileRecording | `api/profilerecording/v1alpha1` | `api/profilerecording/v1` |
| ProfileBinding | `api/profilebinding/v1alpha1` | `api/profilebinding/v1` |
| SPOD | `api/spod/v1alpha1` | `api/spod/v1` |
| SecurityProfileNodeStatus | `api/secprofnodestatus/v1alpha1` | `api/secprofnodestatus/v1` |

### Struct compatibility

The v1 Go types have the fields of the old API versions of 1.0.x, so code
written against 1.0.x mostly compiles after updating the import paths. The
exceptions:

- A few fields which are a plain `string` in the old API versions have a named
  type in v1: `SPODEnricherConfig.LogEnricherSource` is a `LogEnricherSource`,
  and `PolicyRef.Kind` of the SELinux profiles is a `PolicyRefKind`. Code which
  assigns a `string` variable to them has to convert it.
- `SchemeBuilder` is a `runtime.SchemeBuilder` of apimachinery instead of the
  `*scheme.Builder` of controller-runtime. `AddToScheme` and `GroupVersion`
  work as before, but code which calls `SchemeBuilder.Register` with objects
  has to register them with a function, or use `AddToScheme`.

Code written against 0.10.x also has to follow the
[field changes](#field-changes-from-010x): for example, the SPOD settings moved
into the `Selinux`, `Enricher`, `Webhook`, `Scheduling` and `Security` structs,
`AppArmorProfileSpec.ComplainMode` became `Mode`, and
`SelinuxProfileSpec.Permissive` became `Mode`. Several optional fields also
changed from values to pointers, for example the `bool` switches of the SPOD,
which are `*bool` now.

### Enum constants

The Go constant values changed to PascalCase. Update any code that compares
against or assigns these constants:

```go
// Before (v1alpha1)
if spod.Status.State == spodv1alpha1.SPODStatePending { // "PENDING"
    // ...
}
recording.Spec.Recorder = profilerecordingv1alpha1.ProfileRecorderLogs // "logs"

// After (v1)
if spod.Status.State == spodv1.SPODStatePending { // "Pending"
    // ...
}
recording.Spec.Recorder = profilerecordingv1.ProfileRecorderLogs // "Logs"
```

If your code compares against hardcoded string literals instead of the provided
constants, update those strings to PascalCase as shown in the
[enum value changes](#enum-value-changes) table above.

### Registering the v1 scheme

Update your scheme registration to use the v1 packages:

```go
// Before
import spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
spodv1alpha1.AddToScheme(scheme)

// After
import spodv1 "sigs.k8s.io/security-profiles-operator/api/spod/v1"
spodv1.AddToScheme(scheme)
```
