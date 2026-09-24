# Migration Guide: API Graduation to v1

Security Profiles Operator (SPO) 1.0.0 graduates all CRD APIs from alpha/beta to v1. SPO 1.1.0 removed the old API versions. This document covers what changed, how to upgrade, and what you should update. For general installation and usage instructions, see the [documentation](../installation-usage.md).

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
   operator and the daemon to become ready.

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

4. **Upgrade to 1.1.x.**

## Recommended actions

Update everything that references the SPO APIs to v1:

1. **Update YAML manifests.** Change `apiVersion` from
   `security-profiles-operator.x-k8s.io/v1alpha1` (or `v1alpha2`, `v1beta1`)
   to `security-profiles-operator.x-k8s.io/v1`.

2. **Update enum values in manifests.** If you reference enum fields in
   manifests or scripts, update them to PascalCase (see table above).

3. **Update Go client imports.** If you consume the SPO API types in Go code,
   update imports from `api/*/v1alpha1` to `api/*/v1`. For example:
   ```go
   // Before
   import profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"

   // After
   import profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
   ```

4. **Update scripts that parse enum strings.** If automation or monitoring
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

For CRDs without enum changes (SeccompProfile, SelinuxProfile, AppArmorProfile,
ProfileBinding), only the `apiVersion` line needs updating.

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

The v1 Go types are structurally identical to their predecessors. Field names,
types, and JSON tags are unchanged. After updating your import paths, your code
should compile without modifications to struct field access.

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
