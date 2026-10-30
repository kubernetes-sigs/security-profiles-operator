# Security profiles

[Documentation](README.md) | [Installation](installation.md) | [Configuration](configuration.md) | **Profiles** | [Recording](recording.md) | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

This page describes how to create, install and use seccomp, AppArmor and
SELinux profiles, and how to bind them to workloads. Recording profiles from a
running workload is described in [Recording profiles](recording.md), auditing
the activity in pods with the JSON enricher in
[Audit logging](audit-logging-guide.md).

<!-- toc -->
- [Seccomp profiles](#seccomp-profiles)
  - [Create a seccomp profile](#create-a-seccomp-profile)
  - [Use a seccomp profile](#use-a-seccomp-profile)
- [Base profiles](#base-profiles)
  - [Base syscalls for a container runtime](#base-syscalls-for-a-container-runtime)
  - [Base profiles from OCI registries](#base-profiles-from-oci-registries)
  - [Verify the signatures of OCI base profiles](#verify-the-signatures-of-oci-base-profiles)
- [AppArmor profiles](#apparmor-profiles)
  - [Enable AppArmor](#enable-apparmor)
  - [Create an AppArmor profile](#create-an-apparmor-profile)
  - [Use an AppArmor profile](#use-an-apparmor-profile)
- [SELinux profiles](#selinux-profiles)
  - [Enable SELinux](#enable-selinux)
  - [SelinuxProfile and RawSelinuxProfile](#selinuxprofile-and-rawselinuxprofile)
  - [Denied types, classes and permissions](#denied-types-classes-and-permissions)
  - [Create a SELinux profile](#create-a-selinux-profile)
  - [Create a raw SELinux profile](#create-a-raw-selinux-profile)
  - [Make a SELinux profile permissive](#make-a-selinux-profile-permissive)
  - [Use a SELinux profile](#use-a-selinux-profile)
  - [Use a SELinux profile on OpenShift](#use-a-selinux-profile-on-openshift)
- [Bind workloads to profiles](#bind-workloads-to-profiles)
  - [Binding precedence and status](#binding-precedence-and-status)
- [Profile reference](#profile-reference)
  - [Common fields](#common-fields)
  - [SeccompProfile](#seccompprofile)
  - [AppArmorProfile](#apparmorprofile)
  - [SelinuxProfile](#selinuxprofile)
  - [RawSelinuxProfile](#rawselinuxprofile)
  - [ProfileBinding](#profilebinding)
  - [SecurityProfilesOperatorDaemon](#securityprofilesoperatordaemon)
<!-- /toc -->

## Seccomp profiles

### Create a seccomp profile

Use the `SeccompProfile` kind to create profiles, for example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
```

[`seccompprofile.yaml`](../examples/seccompprofile.yaml) holds a few more
examples, which the [quick start](../README.md#quick-start) installs. The
daemon saves the profile on each node at the path:

`/var/lib/kubelet/seccomp/operator/profile1.json`

An init container of the daemon sets up the root directory of the operator, so
that the daemon can run without root UID and GID. It creates a symlink from the
rootless profile storage `/var/lib/security-profiles-operator` to the seccomp
directory inside of the kubelet root, `/var/lib/kubelet/seccomp/operator`. For
a kubelet with another root directory, see
[Configure a custom kubelet root directory](configuration.md#configure-a-custom-kubelet-root-directory).

The SPOD can restrict the syscalls and actions which seccomp profiles may
allow. The daemons reject profiles which allow others, and the operator
deletes them when the lists change, see
[Restrict the allowed syscalls in seccomp profiles](configuration.md#restrict-the-allowed-syscalls-in-seccomp-profiles).

### Use a seccomp profile

Create a pod using one of the created profiles. The profile can be specified
as part of the pod's security context:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/profile1.json
  containers:
    - name: test-container
      image: nginx
```

The `status.localhostProfile` attribute of the seccomp profile holds the path
to use, which the `wide` output mode shows:

```console
$ kubectl get seccompprofile profile1 --output wide
NAME       STATUS      AGE   LOCALHOSTPROFILE
profile1   Installed   14s   operator/profile1.json
```

You can apply the profile to an existing application, such as a Deployment or
DaemonSet:

```shell
kubectl --namespace my-namespace patch deployment myapp --patch '{"spec": {"template": {"spec": {"securityContext": {"seccompProfile": {"type": "Localhost", "localhostProfile": "'$(kubectl get seccompprofile profile1 --output=jsonpath='{.status.localhostProfile}')'"}}}}}}'
```

The pods of the Deployment get restarted automatically. Check that the
profile was applied:

```console
$ kubectl --namespace my-namespace get deployment myapp --output=jsonpath='{.spec.template.spec.securityContext}' | jq .
{
  "seccompProfile": {
    "localhostProfile": "operator/profile1.json",
    "type": "Localhost"
  }
}
```

A security profile that is in use by existing pods cannot be deleted until the
pods exit or are removed, the profile deletion is protected by finalizers.
Completed pods, like the ones of a finished Job, do not count as using the
profile. The `status.activeWorkloads` of a profile lists the first 1000 pods
using it and `status.activeWorkloadsCount` counts all of them.

To apply a profile without changing the workload, use a
[ProfileBinding](#bind-workloads-to-profiles).

## Base profiles

### Base syscalls for a container runtime

A container runtime like [runc](https://github.com/opencontainers/runc) needs
a few syscalls to start a container, before the process of the container
runs. [The examples](../examples/baseprofile-runc.yaml) hold a profile with
these syscalls, named after the runc version it was recorded with. A profile
which sets it as `baseProfileName` gets its syscalls merged in, so that the
profile only has to list the syscalls of the application. The operator does
not ship the base profiles, so apply the example first, then refer to it by
its name. For example:

```shell
kubectl apply -f examples/baseprofile-runc.yaml
```

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: runc-v1.5.2
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - exit_group
```

For [crun](https://github.com/containers/crun), use the
[corresponding example profile](../examples/baseprofile-crun.yaml).

A base profile may set a `baseProfileName` itself, the operator resolves up to
15 stacked profiles. Because the resulting syscalls are not visible in the
profile, the operator annotates the profile with them:

```console
$ kubectl describe seccompprofile profile1
Name:         profile1
Labels:       spo.x-k8s.io/profile-id=SeccompProfile-profile1
Annotations:  syscalls:
                [{"names":["arch_prctl","brk","capget","capset","chdir","clone","close","dup3","epoll_create1","epoll_ctl","epoll_pwait","execve","exit_gr...
API Version:  security-profiles-operator.x-k8s.io/v1
```

If an `oci://` base profile is involved, each node pulls it for its own
architecture, so the result can differ between architectures. The annotation
is then named after the architecture of the node, for example `syscalls-amd64`
and `syscalls-arm64`.

### Base profiles from OCI registries

The operator pulls base profiles from container registries which support OCI
artifacts. Prefix the `baseProfileName` with `oci://` to use one:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: oci://registry.k8s.io/security-profiles-operator/base/runc:v1.5.2
```

The resulting profile `profile1` then contains all syscalls of the remote
`runc` profile. A base profile can also be referenced by its digest, like
`oci://registry.k8s.io/security-profiles-operator/base/runc@sha256:380…`. The
artifacts have to be signed with [sigstore (cosign)](https://github.com/sigstore/cosign),
otherwise the operator rejects them, see
[Verify the signatures of OCI base profiles](#verify-the-signatures-of-oci-base-profiles).
An artifact can hold profiles for several architectures, the operator selects
the one of the node and falls back to a default profile.

The project publishes the base profiles of [the examples](../examples) as
signed OCI artifacts at `registry.k8s.io/security-profiles-operator/base/<runtime>`,
tagged with the runtime version they were recorded against.
`crane ls registry.k8s.io/security-profiles-operator/base/crun` lists the
published versions, see [base profiles](release-baseprofiles.md) for how they
are recorded and published and
[verifying the released artifacts](verification.md#security-profiles) for
their signatures.

Base profiles can also be runtime format artifacts as defined by
[KEP-6061](https://github.com/kubernetes/enhancements/issues/6061): a single
layer containing an OCI runtime-spec seccomp profile in JSON with the media
type `application/vnd.cncf.seccomp-profile.config.v1+json`, as pushed by
`spoc push` from a raw JSON input (see
[cli.md](cli.md#pushing-profiles-for-container-runtimes)). The operator merges
them like profile CRD artifacts, which means only `spec.syscalls` of the base
profile gets unioned into the referencing profile. All other fields are
ignored, including the ones the CRD cannot express such as `defaultErrnoRet`.

The daemon caches pulled artifacts for up to 24 hours and up to 1000 profiles.
It pulls them again after that time, when the cache is full or when the daemon
restarts. Using a cached profile does not extend its cache time, so a base
profile referenced by tag picks up a new version within 24 hours no matter how
often it is used. Reference the base profile by digest to pin the exact
content.

A few limits apply to base profiles pulled by the operator:

- The pull is anonymous. The daemon has no registry credentials, so the
  artifact and its signature have to be publicly readable.
- Every blob of the artifact has to be at most 1 MiB, the size limit container
  runtimes apply to seccomp profile artifacts. Bigger blobs fail the pull
  before they are fetched.
- Signature verification accepts any valid signature by default, see
  [Verify the signatures of OCI base profiles](#verify-the-signatures-of-oci-base-profiles)
  and the [security model](security-model.md#oci-artifact-signature-verification)
  for how to constrain it to the signers you trust. Disabling verification via
  `spec.security.disableOciArtifactSignatureVerification` makes the operator
  use whatever the registry serves.

### Verify the signatures of OCI base profiles

By default, the signatures of OCI base profiles are verified keyless against
`spec.security.allowedIdentityRegexp` and `allowedOidcIssuerRegexp` of the
SPOD. `spec.security.signatureVerification` pins the signer of base profiles
outside of the official repositories (`registry.k8s.io/security-profiles-operator/`
and its staging repository) further. Official base profiles are verified
against the official keyless signers instead, so that a key or identity for
private base profiles does not break them. Only `trustedRootConfigMapRef` and
`offline` apply to official base profiles as well, so that air-gapped clusters
can verify them against a copy of the public Sigstore trusted root.

Both regexps default to `.*`. Without any further configuration, a private base
profile is therefore accepted with a valid signature of any signer, for example
of anybody who signs it keyless through the public Sigstore instance. The
signature then only proves that the artifact was signed, not who signed it.
Unlike `signatureVerification`, the regexps apply to the official base profiles
too once either of them differs from `.*`, so the official base profiles then
fail to verify unless the regexps also match the official signers. Pin the
signer of your private base profiles with the `signatureVerification` settings
below instead, for example to the workflow which signs them:

```yaml
spec:
  security:
    signatureVerification:
      allowedIdentity: https://github.com/my-org/my-profiles/.github/workflows/sign.yml@refs/heads/main
      allowedOidcIssuer: https://token.actions.githubusercontent.com
```

- `allowedIdentity` and `allowedOidcIssuer` require an exact certificate
  identity and OIDC issuer and take precedence over the regexps.
- `publicKeySecretRef` selects a key of a Secret in the operator namespace
  which holds a PEM encoded public key. The signatures are then verified with
  that key and the identity settings are ignored. The signatures need a
  transparency log entry like keyless ones, so signatures made without
  uploading to the transparency log, like with
  `cosign sign --tlog-upload=false`, do not verify.
- `trustedRootConfigMapRef` selects a key of a ConfigMap in the operator
  namespace which holds a Sigstore trusted root JSON, for private Sigstore
  deployments and air-gapped clusters. If it cannot be read or an official
  base profile does not verify against it, the official base profile is
  verified online against the public Sigstore trusted root instead, even with
  `offline: true`.
- `offline: true` verifies without any network access: the transparency log
  entry bundled with the signature is verified against the trusted root of
  `trustedRootConfigMapRef`, which is required then. The daemon keeps no TUF
  cache across restarts, so it cannot verify offline against the public
  trusted root.

The referenced Secret and ConfigMap have to exist. None of this applies while
`disableOciArtifactSignatureVerification` is `true`. For example, to verify the
private base profiles with a cosign public key:

```shell
kubectl -n security-profiles-operator create secret generic profile-signing-key \
  --from-file=cosign.pub
```

```yaml
spec:
  security:
    signatureVerification:
      publicKeySecretRef:
        name: profile-signing-key
        key: cosign.pub
```

## AppArmor profiles

### Enable AppArmor

AppArmor support is disabled by default. Enable it in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
```

The daemon then runs privileged in the host PID namespace and enters the host
mount namespace to install the profiles, see the
[security model](security-model.md).

### Create an AppArmor profile

An `AppArmorProfile` describes the allowed executables, files, network access,
capabilities and ptrace access, which the daemon translates into an AppArmor
policy and loads on each node, see [AppArmorProfile](#apparmorprofile) for the
fields. [`apparmorprofile.yaml`](../examples/apparmorprofile.yaml) holds an
example which denies all file and network access:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: AppArmorProfile
metadata:
  name: test-profile
spec:
  abstract:
    filesystem:
      readOnlyPaths: []
      writeOnlyPaths: []
      readWritePaths: []
    network:
      allowRaw: false
      allowedProtocols:
        allowTcp: false
        allowUdp: false
```

To get a profile which fits a workload, record it with the BPF recorder, see
[Record an AppArmor profile](recording.md#record-an-apparmor-profile).

The operator never overwrites an AppArmor profile it does not own. Ownership is
recorded as a marker comment in the first line of the policy file it installs
under `/etc/apparmor.d`, so an `AppArmorProfile` named after a profile the
distribution ships (`crun`, `busybox`, ...) is rejected with `profile exists`
rather than replacing the host's profile, and deleting such a custom resource
leaves the host's profile alone. A policy file without the marker which the
node status of the profile records as installed on that node was written by
an operator release without the marker, so the operator adopts it and rewrites
it with the marker.

### Use an AppArmor profile

Reference the profile by its name in the security context of the container,
like [`pod-apparmor.yaml`](../examples/pod-apparmor.yaml) does for the profile
above. For a profile `nginx-recording-nginx-container`, recorded as described
in [Record an AppArmor profile](recording.md#record-an-apparmor-profile),
use it in a namespace without a recording, since `AppArmorProfile` objects are
cluster scoped:

```shell
kubectl create ns apparmor-test
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: apparmor-test
  labels:
    app: nginx
spec:
  containers:
    - name: nginx-container
      image: nginx
      securityContext:
        appArmorProfile:
          type: Localhost
          localhostProfile: nginx-recording-nginx-container
EOF
```

The container should run with the profile:

```console
$ kubectl get pod -n apparmor-test
NAME        READY   STATUS    RESTARTS   AGE
nginx-pod   1/1     Running   0          8s
```

Unlike seccomp, AppArmor only needs the name of the profile in the security
context of the container, not a path. See the
[Kubernetes documentation](https://kubernetes.io/docs/tutorials/security/apparmor/)
for more details.

## SELinux profiles

### Enable SELinux

Ensure that the daemon has SELinux enabled. If `spec.selinux.enable` is not
set, SELinux support is enabled on OpenShift and disabled everywhere else:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"selinux":{"enable":true}}}'
```

The daemon installs the SELinux policies through `selinuxd`, see
[Configure SELinux support](configuration.md#configure-selinux-support) for its
image and options.

### SelinuxProfile and RawSelinuxProfile

There are two kinds that can be used to define a SELinux profile:
`SelinuxProfile` and `RawSelinuxProfile`.

`SelinuxProfile` is the default one and the one created by recording. It is
more readable and validates more. Use `RawSelinuxProfile` for an existing
policy in [CIL](https://github.com/SELinuxProject/selinux/blob/main/secilc/docs/README.md),
for example one created with [udica](https://github.com/containers/udica), see
[Create a raw SELinux profile](#create-a-raw-selinux-profile).

In particular, the `SelinuxProfile` kind:

- restricts the profiles to inherit from to other `SelinuxProfile` objects or a
  system-wide profile. Because there are typically many profiles installed on
  the system, but only a subset should be used by cluster workloads, the
  inheritable system profiles are listed in the SPOD in
  `spec.selinux.options.allowedSystemProfiles`, which defaults to
  `["container"]`. Depending on what distribution your nodes run, the base
  profile might vary, on RHEL-based systems, you might want to look at what
  profiles are shipped in the `container-selinux` RPM package.
- performs basic validation of the permissions, classes and labels.
- rejects the types, classes and permissions of a denylist, see
  [Denied types, classes and permissions](#denied-types-classes-and-permissions).
- adds a new keyword `@self` that describes the process using the policy. This
  allows to reuse a policy between workloads and namespaces easily, as the
  "usage" of the policy (see below) is based on the profile name.

### Denied types, classes and permissions

A `SelinuxProfile` which allows one of the denied types, classes or
permissions fails validation: it reports an `Error` status naming the rule and
is not installed. The operator denies these by default, because they would let
a container take over the node or other containers:

- the types `kernel_t`, `kmem_t`, `security_t` and `shadow_t`.
- the classes `capability`, `capability2`, `security` and `system`.
- the permissions `dyntransition`, `load_policy`, `mac_admin`, `mounton`,
  `relabelfrom`, `relabelto`, `setbool`, `setenforce`, `setsecparam` and
  `transition`. `transition` and `dyntransition` would let a container switch
  into another domain.

`spec.selinux.options.deniedTypes`, `deniedClasses` and `deniedPermissions` of
the SPOD deny more of them. `allowedTypes`, `allowedClasses` and
`allowedPermissions` remove entries from the built-in denylist. Use the latter
with care, because they relax a safe default for every profile. Recording does
not leave out the denied entries, so a recorded profile with, for example, a
`capability` rule fails validation until the rule is removed or allowed.

The lists are compared by name, so the CIL keywords `all`, `and`, `not`, `or`,
`range` and `xor` are rejected as permissions. An allow rule on a type
attribute like `file_type` is not rejected either, although the attribute
contains denied types, and grants access to them. To stop that, add the
attribute to `deniedTypes`, which denies attributes by their name as well.

The kernel memory types `memory_device_t` of `/dev/mem`, `/dev/kmem` and
`/dev/port` and `proc_kcore_t` of `/proc/kcore` are not denied by default,
which would break existing profiles. They are recommended `deniedTypes`,
together with the `device_node` attribute, which contains `memory_device_t`:

```yaml
spec:
  selinux:
    options:
      deniedTypes:
        - device_node
        - memory_device_t
        - proc_kcore_t
```

### Create a SELinux profile

Below is an example of a policy that can be used with a non-privileged nginx
workload:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SelinuxProfile
metadata:
  name: nginx-secure
spec:
  allow:
    "@self":
      tcp_socket:
        - listen
    http_cache_port_t:
      tcp_socket:
        - name_bind
    node_t:
      tcp_socket:
        - node_bind
  inherit:
    - kind: System
      name: container
```

[`selinuxprofile.yaml`](../examples/selinuxprofile.yaml) holds another example,
which allows writing to `/var/log`. After the policy is created, wait for
`selinuxd` to install it:

```console
$ kubectl wait --for=condition=ready selinuxprofile nginx-secure
selinuxprofile.security-profiles-operator.x-k8s.io/nginx-secure condition met
```

The CIL policies are placed into an `emptyDir` of the daemon, where you can
view the resulting CIL policy:

```console
$ kubectl -n security-profiles-operator exec -it -c selinuxd spod-fm55x -- sh
sh-4.4# cat /etc/selinux.d/nginx-secure.cil
(block nginx-secure
(blockinherit container)
(allow process nginx-secure.process ( tcp_socket ( listen )))
(allow process http_cache_port_t ( tcp_socket ( name_bind )))
(allow process node_t ( tcp_socket ( node_bind )))
)
```

The binary policies are installed into the system policy store on the nodes,
so you can verify on a node that a policy has been installed:

```console
$ sudo semodule -l | grep nginx-secure
nginx-secure
```

A node reports a SELinux profile as `Installed` once the kernel policy got
reloaded with it, which a `selinux-policy-reload-` Job on the node does in the
operator namespace. While that Job runs, the profile is `InProgress`. If the
Job fails, exceeds its deadline or cannot be created, for example because an
admission policy rejects its pod or its image cannot be pulled, the node
reports `Error` with the reason in the status message of the
`SecurityProfileNodeStatus`. The reload is retried with a growing delay, and
the profile turns `Installed` once a reload succeeded. A failed Job gets
deleted together with its pods right away, so the reason is in the status
message of the node status and the events of the profile. The pods of a
retried Job which is still running show why they do not start:

```shell
kubectl get securityprofilenodestatuses -l spo.x-k8s.io/profile-id=SelinuxProfile-<name> \
  -o custom-columns=NODE:.spec.nodeName,STATUS:.status.status,MESSAGE:.status.message
kubectl -n security-profiles-operator get pods -l app=selinux-policy-reload
```

### Create a raw SELinux profile

A `RawSelinuxProfile` holds a CIL policy in `spec.policy`, like
[`rawselinuxprofile.yaml`](../examples/rawselinuxprofile.yaml):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: RawSelinuxProfile
metadata:
  name: raw-errorlogger
spec:
  policy: |
    (blockinherit container)
    (allow process var_log_t ( dir ( open read getattr lock search ioctl add_name remove_name write )))
    (allow process var_log_t ( file ( getattr read write append ioctl lock map open create )))
```

The daemon places the policy into a CIL block named after the profile, so the
policy does not declare a block itself and its process type is
`<profile name>.process`, like the one of a `SelinuxProfile`. Policies which
udica generates come wrapped in a `(block <name> ...)`: remove that outer
block and keep its content.

A raw policy may only inherit the container templates of udica, for example
with `(blockinherit container)` or `(blockinherit net_container)`. Statements
which change the policy of the whole node are rejected, among them `block`,
`blockstart`, `optional`, `typepermissive`, `booleanif`, `tunable`, the
labeling statements like `filecon`, `portcon` and `genfscon`, and the
declarations of classes, roles, users, sensitivities and categories. The
`rawselinuxprofile-validation.spo.io` webhook rejects such policies when they
are created or updated, and the daemon checks them again before it installs
them.

The statements may still refer to global types, attributes and blocks: allow
rules for global types like `container_t`, `typeattributeset` and `in`
statements can affect other workloads. A raw policy is also not checked
against the denylist of the `SelinuxProfile`. Only cluster admins should be
allowed to write raw SELinux profiles, and `selinux.enableRawSelinuxProfiles:
false` of the SPOD turns them off, see
[Configure SELinux support](configuration.md#configure-selinux-support).

### Make a SELinux profile permissive

Similarly to how a `SeccompProfile` might have a default action `SCMP_ACT_LOG`
which would merely log violations of the policy, but not actually block the
container from executing, a `SelinuxProfile` can be marked as permissive by
setting `.spec.mode` to `Permissive`. This mode might be useful when the policy
is known or suspected to be incomplete and you'd prefer to just watch for
subsequent AVC denials after deploying the policy.

A permissive domain gets every access it asks for, including the types, classes
and permissions which the SPOD denies. To keep the profiles from bypassing the
denylist this way, reject permissive profiles:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge \
  -p '{"spec":{"selinux":{"options":{"allowPermissiveProfiles":false}}}}'
```

A permissive profile and every profile which inherits from it then fail
validation and report an error, so they are neither installed nor updated. A
policy which a node loaded already stays loaded until the profile is deleted.

### Use a SELinux profile

SELinux profiles are referenced based on their `USAGE` type name, which is
`<profile name>.process`. For the profile `nginx-recording-nginx-container`,
recorded as described in
[Record a SELinux profile](recording.md#record-a-selinux-profile):

```console
$ kubectl get selinuxprofile
NAME                              USAGE                                     STATUS      AGE
nginx-recording-nginx-container   nginx-recording-nginx-container.process   Installed   2m
```

Use this SELinux type in the `.spec.containers[].securityContext.seLinuxOptions`
attribute of the workload, which runs the image the profile was recorded from:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-secure
  namespace: spo-selinux
spec:
  containers:
    - name: nginx-container
      image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
      securityContext:
        seLinuxOptions:
          type: nginx-recording-nginx-container.process
```

The pod should start and run. Only the `privileged`
[Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged)
allows a custom SELinux type, so the namespace has to run on it if the cluster
enforces [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/),
like the `spo-selinux` namespace of the recording. In contrast, even the
`restricted` Pod Security Standard allows `Localhost` seccomp profiles.

### Use a SELinux profile on OpenShift

On OpenShift, the security context constraints (SCCs) decide which SELinux
types a pod may use. The default `restricted-v2` SCC sets the SELinux context
of the pods itself and rejects a custom type. The pods of a replicating
controller like a Deployment are created with the identity of their service
account, not the one of the user who creates the Deployment, so they get the
SCCs of the service account.

An SCC with `seLinuxContext: RunAsAny`, like the `privileged` SCC, allows any
type, but it is safer to allow the workload only the type of its profile. This
SCC is based on `restricted-v2` and sets the type of the profile
`nginx-recording-nginx-container` from [Use a SELinux profile](#use-a-selinux-profile):

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: nginx-secure
  annotations:
    kubernetes.io/description: restricted-v2 with the SELinux type of the nginx-recording-nginx-container profile
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: false
allowPrivilegedContainer: false
allowedCapabilities:
  - NET_BIND_SERVICE
defaultAddCapabilities: null
fsGroup:
  type: MustRunAs
groups: []
priority: 10
readOnlyRootFilesystem: false
requiredDropCapabilities:
  - ALL
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
  seLinuxOptions:
    type: nginx-recording-nginx-container.process
seccompProfiles:
  - runtime/default
supplementalGroups:
  type: RunAsAny
users: []
volumes:
  - configMap
  - csi
  - downwardAPI
  - emptyDir
  - ephemeral
  - persistentVolumeClaim
  - projected
  - secret
```

Allow only the service account of the workload to use the SCC. A common
mistake is to grant a custom SCC to a wide range of users, for example through
the `groups` field or a binding to the `system:authenticated` group, see the
[OpenShift documentation on managing SCCs](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/managing-pod-security-policies).
The service account `nginx-sa` of the namespace `nginx-secure` gets the SCC
through a Role and a RoleBinding:

```shell
kubectl create namespace nginx-secure
```

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nginx-sa
  namespace: nginx-secure
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: use-nginx-secure-scc
  namespace: nginx-secure
rules:
  - apiGroups:
      - security.openshift.io
    resources:
      - securitycontextconstraints
    resourceNames:
      - nginx-secure
    verbs:
      - use
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: use-nginx-secure-scc
  namespace: nginx-secure
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: use-nginx-secure-scc
subjects:
  - kind: ServiceAccount
    name: nginx-sa
    namespace: nginx-secure
```

The Deployment selects the service account and does not set the SELinux type,
the SCC sets it:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-secure
  namespace: nginx-secure
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      serviceAccountName: nginx-sa
      containers:
        - name: nginx-container
          image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
```

The SCC has a `priority`, so that admission prefers it over `restricted-v2`,
which the service account can use as well. Without one, admission picks
between SCCs of the same priority by their restrictiveness and then by name.
The `openshift.io/scc` annotation of the pods names the SCC they got admitted
with, which should be `nginx-secure`.

## Bind workloads to profiles

If you do not want to directly modify the security context of a pod, for
instance if you are deploying a public application, you can use the
`ProfileBinding` resource to bind a security profile to the containers of the
pods of a namespace.

You need to enable the profile binding for a namespace by applying the label
`spo.x-k8s.io/enable-binding`, as following for the `default` namespace of the
examples below:

```shell
kubectl label ns default spo.x-k8s.io/enable-binding=
```

To bind a pod that uses an `nginx:1.23.2` image to the `profile-complain-unsafe`
seccomp profile of [the examples](../examples/seccompprofile.yaml), create a
`ProfileBinding` in the same namespace as the pod (seccomp profiles are
cluster scoped), like [`profilebinding.yaml`](../examples/profilebinding.yaml):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: profile-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain-unsafe
  image: nginx:1.23.2
```

The image of a binding matches a container image if both are the same after
normalizing them like the container runtime does: an image without a registry
is a Docker Hub image, official Docker Hub images get the `library/` namespace,
and an image without a tag or digest gets the `latest` tag. The binding above
therefore also matches `docker.io/library/nginx:1.23.2`, and a binding for
`nginx` matches `nginx:latest`. A binding for a tag cannot know which digest
the tag points to, so it does not match a reference by digest like
`nginx@sha256:…`. A reference with both a tag and a digest gets pulled by its
digest, so only a binding for the digest matches it. Use a `"*"` binding to
enforce a profile independent of the image reference.

You can enable a default profile binding by using the string `"*"` as the image
name. It applies to every container of the pod which no image binding of the
same profile kind binds, see
[the precedence of the bindings](#binding-precedence-and-status).

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: profile-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain-unsafe
  image: "*"
```

By default a binding applies to every pod in the namespace that runs a
container with the matching image. When several workloads share the same image
but need different profiles, you can additionally scope a binding to specific
pods with the optional `podSelector` field. It follows standard label selector
semantics, so the binding is only applied to pods whose labels match the
selector (in addition to the image match).

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: profile-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain-unsafe
  image: nginx:1.23.2
  podSelector:
    matchLabels:
      app: nginx
```

If the pod is already running, it needs to be recreated to pick up the profile
binding. Once the binding is created and the pod is created or recreated, the
seccomp profile should be applied to the container whose image matches the
binding:

```console
$ kubectl get pod test-pod -o jsonpath='{.spec.containers[*].securityContext.seccompProfile}'
{"localhostProfile":"operator/profile-complain-unsafe.json","type":"Localhost"}
```

Binding a SELinux or AppArmor profile works in the same way, except you'd use
the `SelinuxProfile` or `AppArmorProfile` kind. Bindings to a
`RawSelinuxProfile` are not supported.

### Binding precedence and status

The binding webhook applies the bindings of the pod's namespace when a pod is
created and when ephemeral containers, for example of `kubectl debug`, are
added to a running pod. Other pod updates are not mutated, because the
security context of a pod cannot be changed after its creation.

- Several bindings of the same profile kind can match a container. Bindings
  are evaluated from the oldest to the newest by creation time, with the name
  breaking ties, and the oldest one wins. A newer binding which would bind a
  different profile is not applied: the pod is admitted with an admission
  warning and the binding gets a `ProfileBindingConflict` event.
- Bindings of different kinds do not conflict, so a pod can get a seccomp, a
  SELinux and an AppArmor profile from three bindings.
- A binding for an image takes precedence over a `"*"` wildcard binding of the
  same kind. A wildcard binding sets the profile in the pod security context,
  and overwrites a value of the same kind a container sets itself, unless an
  image binding already bound that container. For ephemeral containers, which
  cannot change the pod security context, the wildcard profile is set on the
  new containers.
- A binding always replaces a security context value of the pod author, so
  that the bound profile cannot be weakened, for example with
  `type: Unconfined`. A `ProfileRecording` with the `Logs` recorder would
  replace the bound seccomp profile or SELinux type of a container with the
  ones of the recording, so it does not record the containers which a
  binding of the same kind binds. The pod is admitted with an admission
  warning and the recording gets a `ContainerBound` event. A binding which
  got applied to the pod, but which the webhook replica does not know yet,
  counts as binding every container of the pod. The `Bpf` recorder
  does not change the security context and records these containers with
  their bound profile. For the same reason, the deprecated
  `container.apparmor.security.beta.kubernetes.io/<container>` annotations of
  the containers an AppArmorProfile gets bound to are removed. The API server
  rejects pods whose deprecated seccomp annotations do not match the seccomp
  profile fields, so the `container.seccomp.security.alpha.kubernetes.io/<container>`
  annotations of the containers a SeccompProfile gets bound to are removed as
  well, and the `seccomp.security.alpha.kubernetes.io/pod` annotation with a
  `"*"` binding.
- Privileged containers usually run unconfined, so a SeccompProfile bound to a
  privileged container likely has no effect, unless the container runtime
  applies seccomp profiles to privileged containers, like CRI-O with
  `privileged_seccomp_profile`. The pod is admitted with an admission warning
  and the binding gets a `PrivilegedContainer` event.
- The bindings only apply when a pod is created, so the image of a container
  of a running pod cannot be changed while an image binding of the namespace
  matches the old or the new image, independent of its `podSelector`. The
  `binding-image.spo.io` validating webhook rejects such updates, recreate the
  pod instead. It follows the `webhook.options` of `binding.spo.io` in the SPOD
  and only gets the pod updates which change an image.
- The names of recorded profiles only consist of the recording and container
  names, so a recording in any namespace can produce the profile a binding
  expects. A binding to a profile recorded in another namespace than the one
  of the pod still applies, because profiles can be shared across namespaces,
  but the pod is admitted with an admission warning and the binding gets a
  `ProfileRecordedInOtherNamespace` event.
- Bindings to a profile which does not exist are skipped and get a
  `ProfileNotFound` event, so that a binding cannot block all pods of a
  namespace. A pod is rejected while the referenced profile exists but has no
  status yet, which means that no node installed it, unless the profile kind
  is disabled in the SPOD. Then the binding is skipped and gets a
  `ProfileWithoutStatus` event. A pod bound to a profile with the `Partial`
  status of a recording which is not merged yet is rejected as well, because
  the nodes never install partial profiles. So is a pod bound to a profile
  which is being deleted and which no pod uses, because the nodes remove it. A
  pod bound to a disabled profile which no pod uses is admitted with an
  admission warning and the binding gets a `ProfileDisabled` event, because
  the nodes do not install it and the containers cannot start until the
  profile gets enabled again.
- Image bindings of images which no container of the pod uses do not get
  their profile looked up, so they neither reject nor delay the pod.
- A binding which is being deleted does not apply to new pods or ephemeral
  containers anymore, the pods it got applied to keep their profiles. Likewise
  a recording which is being deleted does not record new pods.
- Windows pods are never mutated, because the API server rejects seccomp,
  SELinux and AppArmor settings on them.

The names of the bindings applied to a pod are listed in its
`spo.x-k8s.io/profile-bindings` annotation, and up to 1000 of the workloads
using a binding in its `status.activeWorkloads`. The `Ready` condition of a
binding reports whether the referenced profile exists and is installed:

```console
$ kubectl get profilebinding profile-binding -o jsonpath='{.status.conditions[?(@.type=="Ready")]}'
{"lastTransitionTime":"…","message":"SeccompProfile profile-complain-unsafe not found","reason":"Unavailable","status":"False","type":"Ready"}
```

The reason `ProfileNotInstalled` tells that the profile exists, but is not
installed, along with its status, `ProfileKindDisabled` that the profile has
no status because its kind is disabled in the SPOD, and `InvalidPodSelector`
that the `podSelector` cannot be parsed, so that the binding is not applied to
any pod.

## Profile reference

This section lists the spec fields of the profile and binding kinds which the
sections above do not cover in detail. The fields of `ProfileRecording` are
described in the [ProfileRecording reference](recording.md#profilerecording-reference).
`kubectl explain <kind>.spec` prints the complete schema of the installed
CRDs, for example `kubectl explain seccompprofile.spec.syscalls`.

### Common fields

All profile kinds (`SeccompProfile`, `AppArmorProfile`, `SelinuxProfile` and
`RawSelinuxProfile`) share the field `spec.state`, which is `Enabled`
(default) or `Disabled`. The daemon does not install disabled profiles, see
[Record profiles without applying them](recording.md#record-profiles-without-applying-them).

### SeccompProfile

The fields follow the seccomp section of the
[OCI runtime specification](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp),
the daemon writes them to the profile file on each node.

| Field              | Description |
| ------------------ | ----------- |
| `defaultAction`    | Required. The action for syscalls which no rule matches: `SCMP_ACT_KILL`, `SCMP_ACT_KILL_PROCESS`, `SCMP_ACT_KILL_THREAD`, `SCMP_ACT_TRAP`, `SCMP_ACT_ERRNO`, `SCMP_ACT_TRACE`, `SCMP_ACT_ALLOW` or `SCMP_ACT_LOG`. `SCMP_ACT_NOTIFY` is rejected. |
| `baseProfileName`  | A `SeccompProfile` or an `oci://` reference whose syscalls get merged into this profile, see [Base syscalls for a container runtime](#base-syscalls-for-a-container-runtime) and [Base profiles from OCI registries](#base-profiles-from-oci-registries). |
| `architectures`    | The architectures of the syscalls, like `SCMP_ARCH_X86_64` or `SCMP_ARCH_AARCH64`. |
| `syscalls`         | The rules, see below. |
| `flags`            | Flags for seccomp(2): `SECCOMP_FILTER_FLAG_TSYNC`, `SECCOMP_FILTER_FLAG_LOG`, `SECCOMP_FILTER_FLAG_SPEC_ALLOW` and `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`. |
| `listenerPath`     | The UNIX domain socket of a seccomp agent, which receives the syscalls of rules with the `SCMP_ACT_NOTIFY` action. It has to be below `/var/run/security-profiles-operator/` and at most 107 characters long. |
| `listenerMetadata` | Opaque data which the container runtime passes to the seccomp agent of `listenerPath`. |

Each entry of `syscalls` has these fields:

| Field      | Description |
| ---------- | ----------- |
| `names`    | Required. The names of the syscalls, at least one. |
| `action`   | Required. The action for these syscalls, one of the `defaultAction` values or `SCMP_ACT_NOTIFY`. |
| `errnoRet` | The errno which `SCMP_ACT_ERRNO` and `SCMP_ACT_TRACE` return, from 0 to 4095. 0 behaves like an unset value, the container runtime then returns `EPERM`. |
| `args`     | Up to 6 conditions on the syscall arguments, which all have to match. `index` (required, 0 to 5) selects the argument, `op` (required) is one of `SCMP_CMP_NE`, `SCMP_CMP_LT`, `SCMP_CMP_LE`, `SCMP_CMP_EQ`, `SCMP_CMP_GE`, `SCMP_CMP_GT` and `SCMP_CMP_MASKED_EQ`, `value` is the value to compare with, and `valueTwo` the second value of `SCMP_CMP_MASKED_EQ`, which compares `argument & value` with `valueTwo`. |

For example, this profile makes `clone3` fail with `ENOSYS` (38 on most
architectures), so that the C library falls back to `clone`, and only allows
`personality` with the argument `0`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile-args
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
    - action: SCMP_ACT_ERRNO
      errnoRet: 38
      names:
        - clone3
    - action: SCMP_ACT_ERRNO
      names:
        - personality
      args:
        - index: 0
          value: 0
          op: SCMP_CMP_NE
```

### AppArmorProfile

`spec.mode` is `Enforce` (default) or `Complain`, which logs violations instead
of denying them. `spec.abstract` describes the profile, which the daemon
translates into an AppArmor policy. Its fields are:

| Field                                           | Description |
| ----------------------------------------------- | ----------- |
| `executable.allowedExecutables`                 | Absolute paths of the programs which may be executed (`ixr`). |
| `executable.allowedLibraries`                   | Absolute paths of the libraries which may be mapped and read (`mr`). |
| `filesystem.readOnlyPaths`                      | Paths which may be read (`r`). In `Enforce` mode, writing, linking and locking them is denied. |
| `filesystem.writeOnlyPaths`                     | Paths which may be written, linked and locked (`wlk`). In `Enforce` mode, reading them is denied. |
| `filesystem.readWritePaths`                     | Paths which may be read, written, linked and locked (`rwlk`). |
| `network.allowRaw`                              | Allows raw sockets. If `network` is set without it, raw sockets are denied in `Enforce` mode. |
| `network.allowedProtocols.allowTcp`, `allowUdp` | Allow TCP and UDP sockets. |
| `capability.allowedCapabilities`                | Linux capabilities in lower case without the `CAP_` prefix, like `net_bind_service`. `sys_rawio` additionally allows `mount`, `remount`, `umount` and running `fsck`. |
| `ptrace.allowedAccess`                          | Required if `ptrace` is set. One to four of `read`, `readby`, `trace` and `tracedby`, rendered as a single `ptrace (...)` rule. |
| `ptrace.peer`                                   | Limits the ptrace rule to processes confined by matching profiles, for example `@{profile_name}` for the profile itself. Without it, the rule applies to every process. |

The paths are absolute and may use the AppArmor globs `*`, `**` and `?` as well
as variables like `@{pid}`. Apart from variables, they may only contain
letters, digits, spaces and the characters `_`, `.`, `/`, `*`, `?`, `+`, `@`
and `-`. Other characters, like commas, quotes, braces, `:`, `=` or the
AppArmor character classes in `[]`, are rejected. AppArmor denies everything
which the policy does not allow, apart from the `abstractions/base` rules that
every generated policy includes.

In `Enforce` mode, every generated policy also denies writing to the files
directly in `/proc`, to the subdirectories of `/proc` other than the process
directories and `/proc/sys`, to `/proc/sys` apart from
`/proc/sys/kernel/shm*`, as well as any access to
`/proc/sysrq-trigger`, `/proc/mem`, `/proc/kmem`, `/proc/kcore` and
`/sys/firmware/efi/efivars`. These deny rules win over `readWritePaths` and
`writeOnlyPaths` entries for the same files.

The deny rules of `readOnlyPaths` and `writeOnlyPaths` win over every rule
which allows the same files as well. With `readOnlyPaths: [/etc/**]` and
`readWritePaths: [/etc/app/state]`, `/etc/app/state` cannot be written, and an
executable or library below a `writeOnlyPaths` entry cannot be read. The
daemon logs a warning once per profile generation for a path which falls under
the glob of a conflicting one, which does not catch every overlap of two
globs.

Entries of the form `ptrace (read),` in the path lists of `filesystem` or
`executable` are deprecated and will be removed in a future API version. They
are still accepted and rendered as ptrace rules for every peer, and the daemon
logs a warning for them. Use `ptrace` instead:

```yaml
spec:
  abstract:
    ptrace:
      allowedAccess:
        - read
      peer: "@{profile_name}"
```

### SelinuxProfile

The name of a `SelinuxProfile` becomes the name of a CIL block, so it has to
start with a letter and may only contain lowercase alphanumeric characters and
`-`. The `status.usage` holds the SELinux type to use in the workload,
`<name>.process`.

| Field     | Description |
| --------- | ----------- |
| `inherit` | The policies the profile inherits from. Each entry has a `name` and a `kind`, which is `System` (default) for a system policy listed in `spec.selinux.options.allowedSystemProfiles` of the SPOD, or `SelinuxProfile` for another profile. Defaults to the system policy `container`. |
| `mode`    | `Enforcing` (default) or `Permissive`, see [Make a SELinux profile permissive](#make-a-selinux-profile-permissive). |
| `allow`   | The allow rules. It maps SELinux types, or `@self` for the type of the profile itself, to object classes and these to their permissions. Up to 1024 types and up to 256 classes per type. The names may only contain alphanumeric characters, `.`, `-` and `_`. Denied entries fail validation, see [Denied types, classes and permissions](#denied-types-classes-and-permissions). |

### RawSelinuxProfile

The name of a `RawSelinuxProfile` follows the same rules as the one of a
`SelinuxProfile`. `spec.policy` holds the CIL policy, at most 500000
characters, see [Create a raw SELinux profile](#create-a-raw-selinux-profile).

### ProfileBinding

| Field             | Description |
| ----------------- | ----------- |
| `profileRef.kind` | Required. `SeccompProfile`, `SelinuxProfile` or `AppArmorProfile`. |
| `profileRef.name` | Required. The name of the cluster scoped profile. |
| `image`           | Required. The container image to bind the profile to, or `"*"` for all containers, see [Bind workloads to profiles](#bind-workloads-to-profiles). |
| `podSelector`     | Limits the binding to the pods of the namespace whose labels match. Without it, the binding applies to all pods of the namespace. |

### SecurityProfilesOperatorDaemon

The SPOD configures the operator and its daemon. [SPOD fields](configuration.md#spod-fields)
lists its `spec` fields and the sections which describe them, and
`kubectl explain spod.spec` prints all fields with their defaults.
