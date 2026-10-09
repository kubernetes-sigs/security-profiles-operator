# Security Model

This security model aims to clarify the project's current security position against industry 
recommendations and general security best practices. The information provided here should make 
it easier for security teams from highly regulated sectors to assess and use SPO for their workloads.

The SPO project strives to maintain the [least privilege principle], by trying to run with 
the bare minimum privileges for the least amount of time possible. This approach decreases
the attack surface and the window of opportunity in which it can be abused.

Note that this is an on-going effort, and may change over time as new features are developed.

## Host Isolation (a.k.a. Pod Security / Security Context)

Details the security requirements to run SPO from a host isolation perspective. 

### Initialisation

Seccomp leverages the `non-root-enabler` init container to setup an initial symlink as `root`, so
the daemon can then operate as a non-root user.

The init container drops all capabilities except:

- `CHOWN`
- `FOWNER`
- `DAC_OVERRIDE`

The init container does not mount the host root filesystem. It only mounts:

- `/var/lib/security-profiles-operator` (created if missing), the operator root which holds the
  profiles and is handed over to the non-root user.
- The `seccomp` directory of the kubelet root directory, by default `/var/lib/kubelet` or the
  value of the `KUBELET_DIR` environment variable of the operator, below `/host` (created if
  missing). It creates the `operator` symlink pointing to the operator root there, and copies
  the profiles of the operator itself, like `security-profiles-operator.json`, into it. The rest
  of the kubelet root directory, which holds the secret volumes of all pods, is not mounted.

Nodes can configure a custom kubelet root directory through the
`kubelet.kubernetes.io/directory-location` label. The DaemonSet uses the same pod template on
every node, so the operator mounts each distinct kubelet directory found in these labels into
the init container on all nodes. Kubernetes creates such a directory on nodes where it does not
exist yet, while the init container only writes into the kubelet directory of its own node.
Kubelets can set this label on their own node object, so the operator only accepts directories
whose last path component is `kubelet`, which keeps a single node from getting arbitrary host
directories mounted on all nodes.

When AppArmor is enabled, the profiles are installed through the host mount namespace, which
requires a privileged init container and `HostPID` instead of a host path mount of
`/etc/apparmor.d`. The daemon then runs privileged as well.

The pod does not mount the service account token automatically. Only the containers which talk
to the API server (the `non-root-enabler`, the daemon, the enrichers and the bpf recorder) get
a projected token.


### Running Mode

The running permissions for the three core technologies supported: 

|                                  | Seccomp     | SELinux     | AppArmor    |
|----------------------------------|:-----------:|:-----------:|:-----------:|
|               Requires root user | No          | Yes         | Yes         |
|                 Requires HostPID | No          | No          | Yes         |
|  Requires "privileged container" | No          | Yes (1)     | Yes (4)     |
|     Requires SSH Access to nodes | No          | No          | No          |
| Access to host's mount namespace | No          | Yes         | On Demand   |
|                 AppArmor Profile | `default`   | `default`   | `spo-apparmor` |
|                     SELinux type | `spc_t`     | `spc_t` (2) | `spc_t`     |
|                  Seccomp Profile | `security-profiles-operator.json` (3) | same (3) | none (4) |

1. The `selinux-shared-policies-copier` init container runs privileged to reload the kernel
   policy with `semodule -R`. The long running `selinuxd` container is not privileged, adds the
   `CHOWN`, `FOWNER`, `FSETID` and `DAC_OVERRIDE` capabilities to the runtime defaults, and runs
   with the `selinuxd.process` type.
2. The type can be changed through `spec.selinux.typeTag` of the `spod` resource, for
   example to `unconfined_t` on Flatcar Linux.
3. The daemon container runs with the Localhost seccomp profile `security-profiles-operator.json`,
   which the operator ships in the `security-profiles-operator-profile` ConfigMap and the
   `non-root-enabler` copies into the `seccomp` directory of the kubelet. The pod level default
   is `RuntimeDefault`.
4. With AppArmor enabled the daemon and the `non-root-enabler` run privileged, see
   [Initialisation](#initialisation), so the container runtime does not apply a seccomp profile,
   and CRI-O no AppArmor profile either.

The operator and webhook deployments run as non-root with a read-only root filesystem, all
capabilities dropped, privilege escalation disabled and the `RuntimeDefault` seccomp profile.
On OpenShift they are pinned to the `restricted-v2` SCC through the
`openshift.io/required-scc` annotation. Only the `spod` DaemonSet uses the `privileged` SCC.


#### Host Paths

Throughout their operation they require read and write permissions into host paths:

- `/var/lib/security-profiles-operator` (seccomp profiles, linked from the kubelet `seccomp`
  directory)
- `/etc/selinux`, `/var/lib/selinux` and `/sys/fs/selinux` (only when SELinux is enabled)
- `/etc/apparmor.d` (only when AppArmor is enabled, through the host mount namespace)

Host paths of optional features are only mounted when the feature is enabled, and read-only
unless noted otherwise: the audit and syslog directories for the JSON enricher and the log
enricher with the default `auditd` source, `/sys/kernel/debug` and `/sys/kernel/tracing` for the
JSON enricher, and `/sys/kernel/debug`, `/sys/kernel/security`, `/sys/kernel/tracing` and
`/sys/fs/cgroup` for the bpf recorder.

#### Metrics

The metrics endpoints of the operator, the webhook and the daemon are served via TLS and
require a client which is authenticated and authorized through a `TokenReview` and a
`SubjectAccessReview`, for example with the `spo-metrics-client` ClusterRole. The operator and
the webhook serve them on port 8443. Only the daemon endpoint can be opened up through
`spec.enableInsecureMetricsAccess` of the `spod` resource.

The `spo-metrics-client` ClusterRole only allows reading the metrics paths. It is bound to the
dedicated `spo-metrics-client` ServiceAccount of the operator namespace, which does not mount
its token into pods. The `spo-metrics-client-token` Secret holds a long lived token of that
ServiceAccount for the `ServiceMonitor` of the operator. Pods running with the `default` ServiceAccount of the
operator namespace have no access to the metrics.

### Profile Generation Mode (auto-generating security profiles)

Profile generation features are optional and are not intended to be executed at production environments. 
Ideally such features would be used as part of your software development lifecycle, so you can detect and 
respond to change in profiles, which can _later_ be enforced once deployed in production.

During the execution in profile generation mode, the observed applications may run less restricted than it 
would otherwise, to allow for their operations to be observed and recorded. Keep this in mind when using it
against workloads you may not trust.

Each recorder and enricher runs in a container of its own:

|                                  | Log enricher | JSON enricher | BPF recorder |
|----------------------------------|:------------:|:-------------:|:------------:|
|               Requires root user | Yes          | Yes           | Yes          |
|                 Requires HostPID | Yes          | Yes           | Yes          |
|  Requires "privileged container" | No (1)       | No (2)        | No (3)       |
|     Requires SSH Access to nodes | No           | No            | No           |
|                 AppArmor Profile | `default`    | `default`     | `bpfrecorder-apparmor` (4) |
|                     SELinux type | `spc_t`      | `spc_t`       | `spc_t`      |
|                  Seccomp Profile | `RuntimeDefault` | `RuntimeDefault` | `bpf-recorder.json` |

1. The log enricher drops all capabilities except `SYS_PTRACE` and `DAC_READ_SEARCH`, which
   it needs to resolve the processes of other containers through `/proc`. With the `Bpf` log
   source it adds `BPF`, `PERFMON` and `SYS_RESOURCE`, and does not mount the host log
   directories.
2. The JSON enricher drops all capabilities except `SYS_PTRACE`, `SYS_RESOURCE`, `BPF`,
   `PERFMON` and `DAC_READ_SEARCH`.
3. The bpf recorder drops all capabilities except `BPF`, `PERFMON`, `SYS_RESOURCE`,
   `SYS_PTRACE`, `DAC_READ_SEARCH` and `CHOWN`. With AppArmor enabled it also keeps
   `SYS_ADMIN`, which Debian kernels require for attaching the tracepoints by default.
4. Only with AppArmor enabled, unconfined otherwise, as the runtime default profile denies
   reading `/proc` of the host processes.

`HostPID` is set for the whole `spod` pod while a recorder or enricher is enabled, to map the
processes to their containers.

The log based recording applies the `operator/log-enricher-trace.json` seccomp profile, which
logs instead of blocking syscalls, and the permissive `selinuxrecording.process` SELinux type to
the recorded containers. Both are installed on every node, and the restricted pod security
standard accepts any Localhost profile. The operator therefore manages the
`spo-recording-profiles` ValidatingAdmissionPolicy, which rejects pods referencing them outside
the namespaces selected by the recording webhook (by default the ones labeled with
`spo.x-k8s.io/enable-recording`). Namespace labels are usually managed by cluster admins, so
tenants cannot grant this to themselves. On clusters without the ValidatingAdmissionPolicy API
the policy is skipped.

The recording annotations of a pod are only accepted if the deployed recording webhook applies
to the pod and its namespace and a `ProfileRecording` of the namespace selects the pod, as the
pod author controls the annotations of the other pods. Profiles recorded into a profile which
already exists, but was not recorded by the same `ProfileRecording`, are dropped. That keeps
recordings from overwriting profiles which were written by an admin or recorded by another
namespace.

## Control Plane RBAC

The project's RBAC requirements are managed in an automated manner based on `+kubebuilder:rbac:` tags. 
To map what code requires which permissions, [search this repo](https://github.com/kubernetes-sigs/security-profiles-operator/search?q=%22%2Bkubebuilder%3Arbac%3A%22&type=code) for it.

At control plane level the [least privilege principle] should also be observed.
A high-level summary of the permissions besides the operator's own API, with the API groups
other than the core group. `hack/verify-security-model.sh` checks that each section names all
API groups of its role.

### security-profiles-operator

- Cluster wide: events (`events.k8s.io`, and core events for the leader election), nodes and
  pods (read), the `security-profiles-operator-profile` ConfigMap (read), tokenreviews
  (`authentication.k8s.io`) and subjectaccessreviews (`authorization.k8s.io`) for the metrics,
  OpenShift clusteroperators and apiservers (`config.openshift.io`, read).
- Mutating and validating webhook configurations (`admissionregistration.k8s.io`): create, and
  read and update only for `spo-mutating-webhook-configuration` and
  `spo-validating-webhook-configuration`.
- ValidatingAdmissionPolicies and their bindings (`admissionregistration.k8s.io`): create, and
  read and update only for `spo-recording-profiles`.
- Operator namespace only: daemonsets and deployments (`apps`), the PodDisruptionBudget of the
  webhook (`policy`), services, servicemonitors (`monitoring.coreos.com`), cert-manager issuers
  and certificates (`cert-manager.io`), leases (`coordination.k8s.io`), and the `restricted-v2`
  SCC (`security.openshift.io`).
- Own API: delete on seccomp profiles, to remove the ones which the allow lists of the `spod`
  resource reject once for the cluster, see
  [Restrict the allowed syscalls](installation.md#restrict-the-allowed-syscalls-in-seccomp-profiles).
  Create on the seccomp, SELinux and AppArmor profiles which the operator ships or merges from
  recordings, but not on raw SELinux profiles. The `*/finalizers` subresources are limited to
  get, update and patch, without delete.

### spod

- Cluster wide: events (`events.k8s.io`), nodes and pods (read), get on namespaces and on the
  `spo-mutating-webhook-configuration` (`admissionregistration.k8s.io`) to check that the
  recording webhook applies to a recorded pod and its namespace, tokenreviews
  (`authentication.k8s.io`) and subjectaccessreviews (`authorization.k8s.io`) for the metrics,
  OpenShift apiservers and clusteroperators (`config.openshift.io`, read), for the TLS profile
  of the metrics endpoint.
- Operator namespace only: jobs (`batch`) to reload SELinux policies, get on secrets and
  configmaps for the public keys and the Sigstore trusted roots of the
  [signature verification](#oci-artifact-signature-verification) of OCI base profiles, and the
  `privileged` SCC (`security.openshift.io`).
- Own API: no delete on seccomp profiles, the daemons reject profiles which the allow lists do
  not allow instead of deleting them. The daemons update the finalizers and labels of the
  profiles and patch the annotations of seccomp profiles, but do not write the profile status,
  which the operator aggregates from the node statuses. Create is limited to the seccomp,
  SELinux and AppArmor profiles which the profile recorder records, raw SELinux profiles cannot
  be created. The `*/finalizers` subresources are limited to get, update and patch, without
  delete.

### spo-webhook

- Cluster wide: events (`events.k8s.io`), tokenreviews (`authentication.k8s.io`) and
  subjectaccessreviews (`authorization.k8s.io`) for the metrics, OpenShift apiservers and
  clusteroperators (`config.openshift.io`, read), and get on pods. The binding and recording
  webhooks take the pods they mutate and the validating webhook the raw SELinux profiles from
  the admission requests, so the webhook has no list or watch on pods and no access to raw
  SELinux profiles. Only the exec metadata webhook gets single pods: an exec request carries
  the `PodExecOptions`, not the pod, so it reads the target pod to skip Windows pods.
- Operator namespace only: leases (`coordination.k8s.io`), and the `restricted-v2` SCC
  (`security.openshift.io`).

## Admission webhooks

The binding and recording webhooks use the `Fail` failure policy with a 10 second timeout,
and only apply to namespaces with the `spo.x-k8s.io/enable-binding` or
`spo.x-k8s.io/enable-recording` label. The binding webhook never applies to the operator
namespace, and also binds ephemeral containers, which get added to running pods for example by
`kubectl debug`. Bindings to profiles which do not exist are skipped. A profile without status
is not installed yet, so pods bound to it are rejected, unless its kind is disabled
in the `spod` resource, in which case the binding is skipped with an event.

The exec metadata webhooks use the `Ignore` failure policy and exclude the `kube-system`,
`kube-public`, `kube-node-lease` and operator namespaces. Other system namespaces, like the
`openshift-*` ones, can be excluded through `spec.webhook.options` of the `spod` resource.


For the most up-to-date rbac requirements refer to the materialised [role.yaml](../deploy/base/role.yaml) file.

## OCI artifact signature verification

Base profiles can be distributed as OCI artifacts and are signature verified on
pull. Sigstore bundles attached through the OCI referrers API are verified if
present, otherwise legacy cosign signature tags. Verification is controlled
through the `spod` resource:

```yaml
spec:
  security:
    disableOciArtifactSignatureVerification: false
    allowedIdentityRegexp: ".*"
    allowedOidcIssuerRegexp: ".*"
```

The shipped defaults for `allowedIdentityRegexp` and `allowedOidcIssuerRegexp`
match any value. With those defaults a signature is accepted regardless of who
produced it, which only proves that the artifact was signed by somebody. An
attacker able to publish to the referenced registry can sign with their own
Fulcio identity and pass verification.

Constrain both fields to the signers you actually trust, for example:

```yaml
spec:
  security:
    allowedIdentityRegexp: "^https://github\\.com/my-org/my-profiles/"
    allowedOidcIssuerRegexp: "^https://token\\.actions\\.githubusercontent\\.com$"
```

The operator logs a warning when it recognises an unconstrained signer pattern,
such as the shipped default, so an unintentionally permissive configuration is
visible in the spod logs. That detection is best effort: an arbitrary regexp
which happens to accept everything cannot be recognised as such.

[least privilege principle]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
