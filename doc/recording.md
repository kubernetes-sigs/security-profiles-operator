# Recording profiles

[Documentation](README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Profiles](profiles.md) | **Recording** | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

The operator records security profiles from running workloads. A
`ProfileRecording` selects the pods to record, and the daemon on each node
records their containers with one of two recorders:

| Recorder | Records                         | Needs                                              |
| -------- | ------------------------------- | -------------------------------------------------- |
| `Logs`   | `SeccompProfile`, `SelinuxProfile` | The [log enricher](#log-enricher) and the audit logs of the node |
| `Bpf`    | `SeccompProfile`, `AppArmorProfile` | The [BPF recorder](#bpf-recorder) and a kernel with BTF |

When a recorded pod goes away, the operator stores the recorded profiles as
profile objects, which the nodes then install like any other profile, see
[Security profiles](profiles.md). For recording outside of Kubernetes, see
`spoc record` in the [CLI](cli.md).

<!-- toc -->
- [Enable recording in a namespace](#enable-recording-in-a-namespace)
- [Names of recorded profiles](#names-of-recorded-profiles)
- [Enable a recorder](#enable-a-recorder)
  - [Log enricher](#log-enricher)
  - [BPF recorder](#bpf-recorder)
- [Record a seccomp profile](#record-a-seccomp-profile)
  - [With the log enricher](#with-the-log-enricher)
  - [With the BPF recorder](#with-the-bpf-recorder)
- [Record an AppArmor profile](#record-an-apparmor-profile)
- [Record a SELinux profile](#record-a-selinux-profile)
- [Record specific containers](#record-specific-containers)
- [Merge per-container profile instances](#merge-per-container-profile-instances)
  - [Syscall coverage annotation](#syscall-coverage-annotation)
- [Record profiles without applying them](#record-profiles-without-applying-them)
- [Filter the enricher logs](#filter-the-enricher-logs)
  - [Rule evaluation](#rule-evaluation)
  - [Filter examples](#filter-examples)
- [ProfileRecording reference](#profilerecording-reference)
<!-- /toc -->

## Enable recording in a namespace

The namespace where the recording takes place needs to be labeled with
`spo.x-k8s.io/enable-recording` to enable recording in that namespace. The
examples without a namespace run in the `default` namespace, which gets
labeled as follows:

```shell
kubectl label ns default spo.x-k8s.io/enable-recording=
```

The value of the namespace label does not matter, only its presence. With
[memory optimization](configuration.md#enable-memory-optimization-in-the-daemon)
enabled, the daemon only records the pods which carry the label
`spo.x-k8s.io/enable-recording: "true"` themselves.

Record the workloads in their own namespace, not in the privileged operator
namespace.

## Names of recorded profiles

A `ProfileRecording` lives in the namespace of the recorded workload, but the
profiles it produces are cluster scoped. Each recorded container results in a
profile named `<recording name>-<container name>`, for example
`test-recording-nginx`, without the namespace. With the default
`mergeStrategy: None`, the profiles of the replicas of a replicating
controller additionally carry the suffix of the pod name, see
[Merge per-container profile instances](#merge-per-container-profile-instances).
Recordings with the same name in different namespaces therefore produce
profiles with the same name, and the first recording which stores a profile
wins: the operator refuses to overwrite it for the other recording, emits a
warning event and drops that recording's data. A recording also never replaces
a profile which was not recorded. Use recording names which are unique across
the cluster, for example by including the namespace in the name.

The name of a recording can have at most 63 characters. The name of a
`SelinuxProfile` recording becomes part of a CIL block name, so it has to
start with a letter and may only contain lowercase alphanumeric characters
and `-`.

## Enable a recorder

Both recorders are disabled by default. The daemon only runs its profile
recorder while the SPOD enables at least one of `enricher.enableLogEnricher`,
`enricher.enableBpfRecorder` and `enricher.enableJsonEnricher`, which also run
the daemon pods with `hostPID`, like `enableAppArmor` does. The `ENABLE_LOG_ENRICHER`, `ENABLE_BPF_RECORDER`
and `ENABLE_JSON_ENRICHER` environment variables of the operator Deployment
enable them as well, which is easier to set at install time, for example
through the `spec.config.env` of the `Subscription` of an OLM installation.
Each enabled recorder runs as a container of the daemon pods.

### Log enricher

The log enricher reads the audit events of the node and adds the pod and
container they belong to. It runs as root in the host PID namespace with the
`SYS_PTRACE` and `DAC_READ_SEARCH` capabilities, so that it can resolve the
processes of all containers on the node, and with `CHOWN` to hand its gRPC
socket over to the daemon. With the default `Auditd` source, it
mounts `/var/log/audit` and `/var/log` of the node read-only, see the
[security model](security-model.md).

One of the following requirements to the Kubernetes node have to be fulfilled
to use the log enricher:

- [auditd][auditd] needs to run and has to be configured to log into
  `/var/log/audit/audit.log`.
- [syslog][syslog] can be used as fallback to auditd and needs to log into
  `/var/log/syslog`. Depending on the system configuration, a printk rate
  limiting may be in place which has direct influence on the log enrichment.
  To disable the rate limiting, set the following sysctls:

  ```shell
  sysctl -w kernel.printk_ratelimit=0
  sysctl -w kernel.printk_ratelimit_burst=0
  ```

[auditd]: https://man7.org/linux/man-pages/man8/auditd.8.html
[syslog]: https://man7.org/linux/man-pages/man3/syslog.3.html

Nodes without these files cannot record with the log enricher. Its BPF
source, see
[Select the log enricher source](configuration.md#select-the-log-enricher-source),
only reports AppArmor events, which the recording from logs does not use, so
use the [BPF recorder](#bpf-recorder) on these nodes instead.

Enable the log enricher in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher":true}}}'
```

The operator then rolls out the `spod` DaemonSet with the `log-enricher`
container, which logs `Starting log-enricher on node` once it runs:

```shell
kubectl -n security-profiles-operator logs --selector name=spod -c log-enricher --tail=-1 --prefix | grep 'Starting log-enricher'
```

Log based recording has no effect if the recorded container is privileged,
that is, the container's security context sets `privileged: true`. Privileged
containers are not subject to SELinux or seccomp policies at all, and the log
based recording makes use of a special seccomp or SELinux profile respectively
to record the syscalls or SELinux events.

### BPF recorder

The [eBPF](https://ebpf.io) based recorder records seccomp and AppArmor
profiles. It needs a kernel which exposes its BTF at `/sys/kernel/btf/vmlinux`.
Recording AppArmor profiles also needs the BPF LSM, which is enabled if
`/sys/kernel/security/lsm` lists `bpf`, for example through the `lsm=` kernel
parameter. Operator builds without libbpf have no BPF recorder, they carry the
`no_bpf` build tag, which the operator logs on startup:

```shell
kubectl -n security-profiles-operator logs --selector name=security-profiles-operator --tail=-1 | grep buildTags
```

Enable the BPF recorder in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableBpfRecorder":true}}}'
```

The operator then rolls out the `spod` DaemonSet with the `bpf-recorder`
container. On startup, the recorder loads its BPF programs and checks them by
starting and stopping a recording, which it logs as
`BPF start/stop self-test successful.`:

```shell
kubectl -n security-profiles-operator logs --selector name=spod -c bpf-recorder --tail=-1 --prefix | grep self-test
```

If the self-test fails, please open an issue with the logs of the
`bpf-recorder` container.

## Record a seccomp profile

### With the log enricher

To record by using the [log enricher](#log-enricher), create a
`ProfileRecording` which is using `recorder: Logs`, like
[`profilerecording-seccomp-logs.yaml`](../examples/profilerecording-seccomp-logs.yaml):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  recorder: Logs
  podSelector:
    matchLabels:
      app: my-app
```

Then create a workload to be recorded, for example two containers within a
single pod:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  labels:
    app: my-app
spec:
  containers:
    - name: nginx
      image: quay.io/security-profiles-operator/test-nginx:1.19.1
    - name: redis
      image: quay.io/security-profiles-operator/redis:6.2.1
```

Once the pod is running:

```console
$ kubectl get pods
NAME     READY   STATUS    RESTARTS   AGE
my-pod   2/2     Running   0          18s
```

The enricher logs an `audit` line for each syscall of those containers:

```console
$ kubectl -n security-profiles-operator logs --since=1m --selector name=spod -c log-enricher | grep '"audit"'
… "audit" logger="log-enricher" timestamp="1625486870.273:187492" type="seccomp" node="worker-0" namespace="default" pod="my-pod" container="redis" executable="/usr/local/bin/redis-server" pid=1847839 syscallID=232 syscallName="epoll_wait"
```

Delete the pod to finish the recording:

```shell
kubectl delete pod my-pod
```

The operator then stores two seccomp profiles:

```console
$ kubectl get sp
NAME                   STATUS      AGE
test-recording-nginx   Installed   15s
test-recording-redis   Installed   15s
```

### With the BPF recorder

To record by using the [BPF recorder](#bpf-recorder), create a
`ProfileRecording` which is using `recorder: Bpf`, like
[`profilerecording-seccomp-bpf.yaml`](../examples/profilerecording-seccomp-bpf.yaml):

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: my-recording
spec:
  kind: SeccompProfile
  recorder: Bpf
  podSelector:
    matchLabels:
      app: my-app
```

Then create a workload to be recorded, for example this one:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
  labels:
    app: my-app
spec:
  containers:
    - name: nginx
      image: quay.io/security-profiles-operator/test-nginx:1.19.1
```

Once the pod is running, delete it to finish the recording:

```shell
kubectl delete pod my-pod
```

The operator then stores the seccomp profile:

```console
$ kubectl get sp
NAME                 STATUS      AGE
my-recording-nginx   Installed   15s
```

## Record an AppArmor profile

AppArmor profiles can only be recorded with the [BPF recorder](#bpf-recorder),
which needs the BPF LSM for them. Create a namespace for the workload and
enable recording in it:

```shell
kubectl create ns spo-test
kubectl label ns spo-test spo.x-k8s.io/enable-recording=
```

Set up an AppArmor profile recording for the `nginx` pods, like
[`profilerecording-apparmor-bpf.yaml`](../examples/profilerecording-apparmor-bpf.yaml):

```shell
kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: nginx-recording
  namespace: spo-test
spec:
  kind: AppArmorProfile
  recorder: Bpf
  podSelector:
    matchLabels:
      app: nginx
EOF
```

Start an nginx container, the operator records an AppArmor profile for it in
the background:

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: spo-test
  labels:
    app: nginx
spec:
  containers:
    - name: nginx-container
      image: nginx
EOF
```

Let the container run for at least a few minutes to make sure that the
recorder sees everything the workload does. Then delete the pod, which makes
the operator store the AppArmor profile and install it on the nodes:

```shell
kubectl delete pod -n spo-test nginx-pod
```

Check that the profile got installed, and inspect its content:

```console
$ kubectl get apparmorprofile
NAME                              STATUS      AGE
nginx-recording-nginx-container   Installed   42h
$ kubectl get apparmorprofile nginx-recording-nginx-container -o yaml
```

[Use an AppArmor profile](profiles.md#use-an-apparmor-profile) shows how a pod
uses it. Restrictive profiles may block sub processes from being created, or a
container from starting successfully. To work around that, set the AppArmor
profile to complain mode by setting `.spec.mode` to `Complain`.

## Record a SELinux profile

SELinux profiles can only be recorded with the [log enricher](#log-enricher),
and the daemon needs [SELinux enabled](profiles.md#enable-selinux). The
recording webhook sets the SELinux type `selinuxrecording.process` in the
security context of the recorded containers, which makes them run permissive
and log their AVC denials.

Only the `privileged` Pod Security Standard allows a custom SELinux type, so
the namespace has to run on it if the cluster enforces
[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/).
On OpenShift, the recorded pods also need an SCC with
`seLinuxContext: RunAsAny`, like the `privileged` SCC, which allows the webhook
to set the type, see
[Use a SELinux profile on OpenShift](profiles.md#use-a-selinux-profile-on-openshift)
for how SCCs apply to pods.

```shell
kubectl create ns spo-selinux
kubectl label ns spo-selinux spo.x-k8s.io/enable-recording= \
  pod-security.kubernetes.io/enforce=privileged
```

Create a `ProfileRecording` which is using `recorder: Logs`, like
[`profilerecording-selinux-logs.yaml`](../examples/profilerecording-selinux-logs.yaml):

```shell
kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: nginx-recording
  namespace: spo-selinux
spec:
  kind: SelinuxProfile
  recorder: Logs
  podSelector:
    matchLabels:
      app: nginx
EOF
```

Start an nginx container, the operator records a SELinux profile for it in the
background:

```shell
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: spo-selinux
  labels:
    app: nginx
spec:
  containers:
    - name: nginx-container
      image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
EOF
```

Let the container run for at least a few minutes to make sure that the
recorder sees everything the workload does. Then delete the pod, which makes
the operator store the SELinux profile and install it on the nodes:

```shell
kubectl delete pod -n spo-selinux nginx-pod
```

Check that the profile got installed, and inspect its content:

```console
$ kubectl get selinuxprofile
NAME                              USAGE                                     STATUS      AGE
nginx-recording-nginx-container   nginx-recording-nginx-container.process   Installed   2m
$ kubectl get selinuxprofile nginx-recording-nginx-container -o yaml
```

A recorded profile which allows one of the
[denied types, classes or permissions](profiles.md#denied-types-classes-and-permissions)
reports an `Error` status instead. [Use a SELinux profile](profiles.md#use-a-selinux-profile)
shows how a pod uses the profile.

## Record specific containers

Without `containers`, a recording records all containers of the selected
pods. To record only some of them, list their names, like
[`profilerecording-seccomp-bpf-specific-container.yaml`](../examples/profilerecording-seccomp-bpf-specific-container.yaml)
does for the `nginx` container of a pod which runs `nginx` and `redis`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  recorder: Bpf
  podSelector:
    matchLabels:
      app: my-app
  containers:
    - nginx
```

## Merge per-container profile instances

By default, each container instance is recorded into a separate profile. This
is mostly visible when recording pods managed by a replicating controller
(Deployment, DaemonSet, etc.). A realistic example might be a workload being
recorded in a test environment where the recorded Deployment consists of
several replicas, only one of which is receiving the test traffic. After the
recording is complete, only the container that was receiving the traffic
would have contained all the syscalls that were actually used.

In this case, it might be useful to merge the per-container profiles into a
single profile. This can be done by setting the `mergeStrategy` attribute to
`Containers` in the `ProfileRecording`. The following example uses a
`SeccompProfile` as the `kind`, but the same applies to `SelinuxProfile` as
well, and to `AppArmorProfile`, which is recorded with `recorder: Bpf`
instead.

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  recorder: Logs
  mergeStrategy: Containers
  podSelector:
    matchLabels:
      app: sp-record
```

Create your workload:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deploy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sp-record
  template:
    metadata:
      labels:
        app: sp-record
    spec:
      containers:
        - name: nginx-record
          image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
          ports:
            - containerPort: 8080
```

The Deployment spawns three replicas. To test the merging feature, perform an
action in one of the pods, for example:

```shell
kubectl exec nginx-deploy-65bcbb956f-gmbrj -- bash -c "mknod /tmp/foo p"
```

To record the individual profiles, delete the Deployment:

```shell
kubectl delete deployment nginx-deploy
```

The operator stores one profile per container. The profiles are marked as
`Partial`, and the daemon does not install partial profiles:

```console
$ kubectl get sp -lspo.x-k8s.io/recording-id=test-recording --show-labels
NAME                                STATUS    AGE     LABELS
test-recording-nginx-record-gmbrj   Partial   2m50s   spo.x-k8s.io/container-id=nginx-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-nginx-record-gmbrj,spo.x-k8s.io/recording-id=test-recording,spo.x-k8s.io/recording-namespace=default
test-recording-nginx-record-lclnb   Partial   2m50s   spo.x-k8s.io/container-id=nginx-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-nginx-record-lclnb,spo.x-k8s.io/recording-id=test-recording,spo.x-k8s.io/recording-namespace=default
test-recording-nginx-record-wdv2r   Partial   2m50s   spo.x-k8s.io/container-id=nginx-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-nginx-record-wdv2r,spo.x-k8s.io/recording-id=test-recording,spo.x-k8s.io/recording-namespace=default
```

The partial profile of the pod where the extra command ran allows `mknod`:

```console
$ kubectl get sp test-recording-nginx-record-gmbrj -o yaml | grep mknod
  - mknod
```

The others do not:

```shell
kubectl get sp test-recording-nginx-record-lclnb -o yaml | grep mknod
kubectl get sp test-recording-nginx-record-wdv2r -o yaml | grep mknod
```

To merge the profiles, delete the profile recording to indicate that you are
finished with recording the workload. The operator then merges the partial
profiles into one profile, which the nodes install:

```console
$ kubectl delete profilerecording test-recording
profilerecording.security-profiles-operator.x-k8s.io "test-recording" deleted
$ kubectl get sp -lspo.x-k8s.io/recording-id=test-recording
NAME                          STATUS      AGE
test-recording-nginx-record   Installed   17m
```

The resulting profile contains all the syscalls that were used by any of the
containers, including the `mknod` syscall:

```console
$ kubectl get sp test-recording-nginx-record -o yaml | grep mknod
  - mknod
```

Profiles are cluster scoped, so the merged profile `<recording>-<container>`
may exist already and belong to a recording with the same name in another
namespace, or not be recorded at all. The partial profiles of that container
are then kept, and the recording stays `Terminating` with a
`MergedProfileConflict` event, until that profile is deleted or labeled with
the `spo.x-k8s.io/recording-id` and `spo.x-k8s.io/recording-namespace` of the
recording. The `ProfileConflict` condition of the recording names such
profiles while it records, see the
[ProfileRecording reference](#profilerecording-reference).

### Syscall coverage annotation

When a `SeccompProfile` is produced by a merge (`mergeStrategy: Containers`),
the resulting profile carries an informational annotation,
`spo.x-k8s.io/syscall-coverage`, that records how the merged allowlist was
assembled from the individual partial profiles. Its value is a small JSON
document:

```json
{
  "version": "v1",
  "total": 3,
  "syscalls": {
    "mknod": 1,
    "read": 3,
    "write": 3
  }
}
```

The semantics are literal, per syscall: `total` is the number of partial
profiles that were collected and included in the merge, and each entry under
`syscalls` is the number of those partial profiles that contained that
syscall. A syscall that appears more than once inside a single partial
profile still counts once for that profile. In the example above, `read` and
`write` were observed in all three recorded containers, while `mknod` was
observed in only one.

A merge adds the partial profiles to the syscalls the profile already holds
from earlier merges of the same recording, for example of partial profiles
which showed up after the first merge, and the counts of the annotation add up
the same way. A profile which was created before the recording belongs to an
earlier recording with the same name and gets replaced, together with its
counts. Syscalls which got into the profile without a merge are not counted:
the ones a node records straight into the profile of a recording which is
already being deleted, and the ones of a profile which was merged before the
annotation existed. The `spo.x-k8s.io/syscall-coverage-partials` annotation
lists the UIDs of the partial profiles of the last merge, so that merging them
again, for example after deleting them failed, does not count them twice.

This is observation coverage, not confidence or probability, and it does not
measure how many times a syscall was invoked. `total` counts the partial
profiles that were actually collected, which is not necessarily the number of
executions that occurred (for example, a recording can be lost if the
operator restarts mid-recording). Recorded replicas usually run identical
images and are therefore correlated rather than independent samples, so the
counts should not be read as a statistical measure.

The annotation is purely informational: it never changes the generated
seccomp allowlist, and the enforced profile is exactly what the merge produces
regardless of these counts. Treat it as a review aid only. Do not remove
syscalls from a generated profile based solely on a low coverage count, since
a syscall observed in only one replica may still be required on a code path
the other replicas did not exercise.

## Record profiles without applying them

In some cases, it might be desirable to record security profiles, but not
install them. Use-cases might include recording profiles in a CI system where
the profiles would be deployed in a subsequent verify run or recording
profiles as part of a build process where the profile would be deployed by
the end-user.

To record profiles without installing them, set the
`disableProfileAfterRecording` attribute to `true` in the `ProfileRecording`.
This option defaults to `false`, which installs the profiles. With
`disableProfileAfterRecording: true`, the operator creates the profiles in the
`Disabled` state, so that the nodes do not install them. Partial disabled
profiles can still be merged and the resulting merged profile is disabled.

On the profile level, this functionality is controlled by the `.spec.state`
field, which defaults to `Enabled`. Profiles can also be created in the
`Disabled` state directly. Disabled profiles, either explicitly or by the
`disableProfileAfterRecording` flag, can be enabled by setting `.spec.state`
to `Enabled` in the profile.

## Filter the enricher logs

The log enricher and the JSON enricher can filter the lines they log. The
filters are configured in the SPOD as a JSON-encoded string containing an
array of filter rules. Two fields are available in `spec.enricher`, each
controlling a different enricher:

- `logEnricherFilters` applies to the [log enricher](#log-enricher).
- `jsonEnricherFilters` applies to the
  [JSON enricher](audit-logging-guide.md).

Both fields are limited to 64 KiB. An enricher whose filters are not valid
JSON fails to start, so check the logs of its container after changing them.
For example, to enable the log enricher with an empty filter list (no custom
filtering):

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher":true,"logEnricherFilters":"[]"}}}'
```

Each rule of the array has these fields:

| Field         | Type             | Description | Example value |
| ------------- | ---------------- | ----------- | ------------- |
| `priority`    | integer          | The order of the rules. Rules with lower priority numbers are evaluated first. | `10`, `100` |
| `level`       | string           | The action if this rule matches a log line: `Metadata` logs the line, `None` drops it. Any other value logs a warning and counts as `Metadata`. | `"Metadata"`, `"None"` |
| `matchKeys`   | array of strings | The keys (field names) of a log line. The rule can match if any of them is present in the log line. A key with a `/` names a nested field of the JSON enricher, see below. A rule without `matchKeys` never matches. | `["namespace"]`, `["resource/namespace"]`, `["requestUID"]` |
| `matchValues` | array of strings | Optional. If set, the values of the matched `matchKeys` in the log line must match at least one of these values. If it is empty or unset, the presence of any of the `matchKeys` is sufficient for a match, regardless of their values. | `["default"]`, `["test"]` |

### Rule evaluation

When an enricher starts, it parses and loads all configured filter rules. For
each log line:

- Rules are evaluated strictly in ascending order of their priority (lower
  numbers are evaluated first).
- The first rule that a log line matches determines its fate. No subsequent
  rules will be evaluated for that particular log line.
- A log line matches a rule if:
  - Any keys specified in `matchKeys` are present in the log line. The log
    enricher emits flat fields like `namespace`, `pod` and `container`. The
    JSON enricher nests them below `resource` and the node name below `node`,
    which a key selects with a `/`, like `resource/namespace`, `resource/pod`,
    `resource/container` or `node/name`. A plain `namespace` key never matches
    a line of the JSON enricher.
  - AND (if `matchValues` is set and not empty): at least one of the values of
    the matched `matchKeys` in the log line matches at least one string in the
    rule's `matchValues`. A value of `matchValues` which is a number, like
    `"232"`, also matches the integer values of the log line, like a
    `syscallID`.
  - A value which is a list, like the `syscalls` of the JSON enricher, matches
    if any of its elements does, and the level of the rule then applies to the
    whole log line.
- If the matching rule's level is `Metadata`, the log line is emitted. If it
  is `None`, the log line is dropped.
- If no rule matches the log line, it is emitted, like with `Metadata`.

### Filter examples

To log only the JSON enricher lines with a `requestUID`, which belong to
`kubectl exec` and node debugging sessions, and drop all others:

```json
[
  {
    "priority": 100,
    "level": "Metadata",
    "matchKeys": ["requestUID"]
  },
  {
    "priority": 999,
    "level": "None",
    "matchKeys": ["version"],
    "matchValues": ["spo/v1_alpha"]
  }
]
```

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher": true, "jsonEnricherFilters": "[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]"}}}'
```

To log the seccomp lines of the log enricher only for the `default` namespace
and drop the seccomp lines of all other namespaces:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher": true, "logEnricherFilters": "[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"namespace\"],\"matchValues\":[\"default\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"type\"],\"matchValues\":[\"seccomp\"]}]"}}}'
```

## ProfileRecording reference

`kubectl explain profilerecording.spec` prints the complete schema of the
installed CRD.

| Field                          | Description |
| ------------------------------ | ----------- |
| `kind`                         | Required. The profile kind to record: `SeccompProfile`, `SelinuxProfile` or `AppArmorProfile`. |
| `recorder`                     | Required. `Logs` or `Bpf`. `SelinuxProfile` recordings require `Logs` and `AppArmorProfile` recordings require `Bpf`. |
| `podSelector`                  | Required. The label selector of the pods to record in the namespace of the recording. An empty selector matches all pods. |
| `containers`                   | The names of the containers to record, at most 63 characters each. Without it, all containers of the selected pods get recorded, see [Record specific containers](#record-specific-containers). |
| `mergeStrategy`                | `None` (default) or `Containers`, see [Merge per-container profile instances](#merge-per-container-profile-instances). |
| `disableProfileAfterRecording` | Creates the recorded profiles in the `Disabled` state, see [Record profiles without applying them](#record-profiles-without-applying-them). |

The status of a `ProfileRecording` carries two conditions:

- `Ready` is `True` if the recording can record. Otherwise its reason tells
  why not:
  - `RecorderDisabled` if neither the SPOD nor the environment variable of
    the operator enables the recorder (`spec.enricher.enableLogEnricher` or
    `ENABLE_LOG_ENRICHER` for `Logs`, `spec.enricher.enableBpfRecorder` or
    `ENABLE_BPF_RECORDER` for `Bpf`).
  - `NamespaceNotEnabled` if the recording webhook does not select the
    namespace, by default because it lacks the
    `spo.x-k8s.io/enable-recording` label.
  - `InvalidPodSelector` if the `podSelector` cannot be parsed.
  - `NoContainersSelected` if `containers` is an empty list, which records no
    container (leave it unset to record all of them).
  - `SelinuxDisabled` if a `SelinuxProfile` recording cannot record because
    the SPOD does not enable SELinux (`spec.selinux.enable`).
  - `Unavailable` if `kind` and `recorder` cannot be combined. The API
    rejects such recordings, so only recordings created before it validated
    the combination can have this reason.
- `ProfileConflict` is `True` with the reason `ProfileOwnedByOther` if
  profiles which the recording would write exist already, but were recorded by
  a recording in another namespace or not recorded at all. The recorded data
  for them gets dropped. The check is best effort: it covers the containers of
  the pods the recording tracks, the merged profiles of its partial profiles,
  and with `mergeStrategy: Containers` the merged profiles of `containers`.
