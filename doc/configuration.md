# Configuration

[Documentation](README.md) | [Installation](installation.md) | **Configuration** | [Profiles](profiles.md) | [Recording](recording.md) | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Feature switches](#feature-switches)
- [SPOD fields](#spod-fields)
- [Environment variables of the operator](#environment-variables-of-the-operator)
- [Configure a custom kubelet root directory](#configure-a-custom-kubelet-root-directory)
- [Set a custom priority class for the daemon](#set-a-custom-priority-class-for-the-daemon)
- [Set the logging verbosity](#set-the-logging-verbosity)
- [Pull images from a private registry](#pull-images-from-a-private-registry)
- [Configure the SELinux type](#configure-the-selinux-type)
- [Configure SELinux support](#configure-selinux-support)
  - [Select the selinuxd image](#select-the-selinuxd-image)
- [Customize the daemon resource requirements](#customize-the-daemon-resource-requirements)
- [Configure the rollout of the daemon](#configure-the-rollout-of-the-daemon)
- [Restrict the allowed syscalls in seccomp profiles](#restrict-the-allowed-syscalls-in-seccomp-profiles)
- [Constrain the scheduling of the daemon](#constrain-the-scheduling-of-the-daemon)
- [Select the log enricher source](#select-the-log-enricher-source)
- [Enable memory optimization in the daemon](#enable-memory-optimization-in-the-daemon)
- [Use a custom <code>/proc</code> location for nested environments like <code>kind</code>](#use-a-custom-proc-location-for-nested-environments-like-kind)
- [Configure the concurrent reconciles of the manager](#configure-the-concurrent-reconciles-of-the-manager)
- [Configure the API server rate limit of the manager](#configure-the-api-server-rate-limit-of-the-manager)
- [Restrict the operator to namespaces](#restrict-the-operator-to-namespaces)
  - [Restrict the operator with the release manifests](#restrict-the-operator-with-the-release-manifests)
  - [Restrict the operator when installing using OLM](#restrict-the-operator-when-installing-using-olm)
  - [OLM install modes and namespaces](#olm-install-modes-and-namespaces)
- [Configure the webhooks](#configure-the-webhooks)
- [Customize the admission policies of the <code>spod</code> service account](#customize-the-admission-policies-of-the-spod-service-account)
<!-- /toc -->

The operator gets configured through the `SecurityProfilesOperatorDaemon`
(SPOD) named `spod` in the operator namespace, which the operator creates if it
is missing. The daemons, the webhooks and the node statuses only read that one,
so the API rejects new objects with another name. Objects with another name
created before are not reconciled and report `UnsupportedName` as reason of
their `Ready` condition, delete them and configure `spod` instead.

The examples on this page patch the SPOD with `kubectl`. The Helm chart renders
the SPOD from its values, see [chart values](installation.md#chart-values), so
set the fields there for Helm installations: a `helm upgrade` can revert the
patched ones. `kubectl explain spod.spec` describes every field.

## Feature switches

The optional features are disabled by default, except for SELinux on
OpenShift:

| Feature | SPOD field | Helm value | Usage |
|---------|------------|------------|-------|
| AppArmor profiles | `enableAppArmor` | `enableAppArmor` | [AppArmor profiles](profiles.md#apparmor-profiles) |
| SELinux profiles | `selinux.enable`, enabled on OpenShift if unset | `selinux.enable` | [SELinux profiles](profiles.md#selinux-profiles), [SELinux support](#configure-selinux-support) |
| Log enricher | `enricher.enableLogEnricher` | `enableLogEnricher` | [Log enricher](recording.md#log-enricher), [log enricher source](#select-the-log-enricher-source) |
| BPF recorder | `enricher.enableBpfRecorder` | `enableBpfRecorder` | [BPF recorder](recording.md#bpf-recorder) |
| JSON enricher | `enricher.enableJsonEnricher` | `enableJsonEnricher` | [Enable the JSON enricher](audit-logging-guide.md#enable-the-json-enricher) |

For example, to enable the log enricher:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge \
  -p '{"spec":{"enricher":{"enableLogEnricher":true}}}'
```

The operator then rolls out the `spod` DaemonSet with the containers of the
enabled features. The log enricher, the BPF recorder, the JSON enricher and
AppArmor run the daemon pods in the host PID namespace, see the
[security model](security-model.md) for the privileges of each feature.

## SPOD fields

The fields of the SPOD spec and where they are documented:

| Field | Section |
|-------|---------|
| `daemonResourceRequirements` | [Customize the daemon resource requirements](#customize-the-daemon-resource-requirements) |
| `daemonUpdateStrategy` | [Configure the rollout of the daemon](#configure-the-rollout-of-the-daemon) |
| `enableAppArmor` | [Feature switches](#feature-switches) |
| `enableInsecureMetricsAccess` | [Metrics](metrics.md) |
| `enableMemoryOptimization` | [Enable memory optimization in the daemon](#enable-memory-optimization-in-the-daemon) |
| `enableProfiling` | [Enable CPU and memory profiling](troubleshooting.md#enable-cpu-and-memory-profiling) |
| `enricher.enableBpfRecorder`, `enricher.enableLogEnricher` | [Enable a recorder](recording.md#enable-a-recorder) |
| `enricher.enableExecMetadata` | [Attribute exec sessions and node debugging](audit-logging-guide.md#attribute-exec-sessions-and-node-debugging) |
| `enricher.enableJsonEnricher`, `enricher.jsonEnricherFilters`, `enricher.jsonEnricherOptions` | [Configure the JSON enricher](audit-logging-guide.md#configure-the-json-enricher) |
| `enricher.logEnricherFilters` | [Filter the enricher logs](recording.md#filter-the-enricher-logs) |
| `enricher.logEnricherSource` | [Select the log enricher source](#select-the-log-enricher-source) |
| `hostProcVolumePath` | [Use a custom `/proc` location](#use-a-custom-proc-location-for-nested-environments-like-kind) |
| `imagePullSecrets` | [Pull images from a private registry](#pull-images-from-a-private-registry) |
| `scheduling.affinity`, `scheduling.tolerations` | [Constrain the scheduling of the daemon](#constrain-the-scheduling-of-the-daemon) |
| `scheduling.priorityClassName` | [Set a custom priority class for the daemon](#set-a-custom-priority-class-for-the-daemon) |
| `security.allowedSeccompActions`, `security.allowedSyscalls` | [Restrict the allowed syscalls in seccomp profiles](#restrict-the-allowed-syscalls-in-seccomp-profiles) |
| `security.allowedIdentityRegexp`, `security.allowedOidcIssuerRegexp`, `security.disableOciArtifactSignatureVerification`, `security.signatureVerification` | [Verify the signatures of OCI base profiles](profiles.md#verify-the-signatures-of-oci-base-profiles) |
| `selinux.customTemplatesConfigMap`, `selinux.enableRawSelinuxProfiles`, `selinux.options` | [Configure SELinux support](#configure-selinux-support) |
| `selinux.enable` | [Feature switches](#feature-switches) |
| `selinux.typeTag` | [Configure the SELinux type](#configure-the-selinux-type) |
| `verbosity` | [Set the logging verbosity](#set-the-logging-verbosity) |
| `webhook.options`, `webhook.staticConfig` | [Configure the webhooks](#configure-the-webhooks) |
| `webhook.tolerations` | [Constrain the scheduling of the daemon](#constrain-the-scheduling-of-the-daemon) |

## Environment variables of the operator

Some settings are environment variables of the `security-profiles-operator`
Deployment instead of SPOD fields, like `KUBELET_DIR`, `RESTRICT_TO_NAMESPACE`,
`SPO_MAX_CONCURRENT_RECONCILES`, `SPO_KUBE_API_QPS`, `SPO_KUBE_API_BURST`,
`MAX_METRIC_SERIES` and `SPO_VERBOSITY`. The
[command line reference](reference/security-profiles-operator.md) lists all of
them. How to set them depends on the installation method:

- Release manifests: set them on the Deployment, for example with
  `kubectl -n security-profiles-operator set env deploy/security-profiles-operator MAX_METRIC_SERIES=50000`.
  Applying the manifest of a new release resets the variables which the
  manifest sets itself, like `KUBELET_DIR`, and keeps the others.
- Helm: set them through the `extraEnv` value of the chart, for example
  `--set 'extraEnv[0].name=MAX_METRIC_SERIES' --set-string 'extraEnv[0].value=50000'`,
  so that they are part of the release. `extraEnv` must not repeat the
  variables which the chart sets itself: `RELATED_IMAGE_SELINUXD*` from the
  `selinuxdImage.*` values, `KUBELET_DIR` from `kubeletDir`,
  `RESTRICT_TO_NAMESPACE` from `restrictToNamespace`, and `OPERATOR_NAMESPACE`,
  `WATCH_NAMESPACE`, `NODE_NAME` and `DISABLE_DEFAULT_SPOD`. A `helm upgrade` resets the variables
  which the chart sets itself.
- OLM: set them in `spec.config.env` of the `Subscription`. OLM reverts the
  changes made to the Deployment directly.

  ```yaml
  spec:
    config:
      env:
        - name: MAX_METRIC_SERIES
          value: "50000"
  ```

  See the
  [OLM documentation](https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/design/subscription-config.md#env)
  for the other fields of `spec.config`.

## Configure a custom kubelet root directory

You can configure a custom kubelet root directory in case your cluster is not
using the default `/var/lib/kubelet` path. Set the environment variable
`KUBELET_DIR` of the operator, see
[environment variables](#environment-variables-of-the-operator). The operator
passes it on to the containers of the `spod` DaemonSet. The Helm chart sets it
through the `kubeletDir` value.

Furthermore, you can configure a custom kubelet root directory for each node or
a pool of worker nodes inside the cluster, by applying the following label to
each node object which has a custom path:

```yaml
kubelet.kubernetes.io/directory-location: mnt-resource-kubelet
```

The value of the label is the kubelet root directory path, with `/` replaced by
`-`. For example the operator translates the value above from
`mnt-resource-kubelet` into the path `/mnt/resource/kubelet`.

The last component of the path has to be `kubelet`, for example
`var-lib-k0s-kubelet` (`/var/lib/k0s/kubelet`) or
`var-snap-microk8s-common-var-lib-kubelet`
(`/var/snap/microk8s/common/var/lib/kubelet`). Kubelets can set this label on
their own node, so the operator ignores other values, reports them as
`InvalidKubeletDirLabel` warning event on the SPOD and uses the default kubelet
root directory for such nodes. This includes paths below the system and
executable directories, like `/usr/bin/kubelet`, and paths below the files and
directories which the kubelet keeps in its root directory, like
`/var/lib/kubelet/cpu_manager_state/kubelet`, where `cpu_manager_state` is a
file.

The `spod` DaemonSet only mounts the kubelet root directories from the host,
not the whole host filesystem. Because the DaemonSet uses the same pod template
on every node, each distinct directory from these labels gets mounted (and
created if missing) on all nodes. Adding a node with a new kubelet root
directory, or changing the label to a new directory, rolls out the DaemonSet on
all nodes. Directories which are no longer referenced by any node, for example
after removing the label or the last node using it, stay mounted until the
DaemonSet gets rolled out for another reason, like a SPOD change or a new
kubelet root directory. A single unavailable daemon pod, for example on a node
which is not ready, does not change that. While no daemon pod is available or
the rollout of the DaemonSet does not finish, for example because a directory
cannot be mounted, the directories which are no longer referenced get removed
right away instead. The [rollout of the daemon](#configure-the-rollout-of-the-daemon)
limits how many daemon pods a broken directory stops at once.

## Set a custom priority class for the daemon

The daemon pods use the `system-node-critical` priority class by default. Set
another one through `scheduling.priorityClassName` of the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"scheduling":{"priorityClassName":"my-priority-class"}}}'
```

This is useful when the daemon pods remain `Pending`, because there isn't
enough capacity on their node.

The pods of the webhook which the operator manages use
`system-cluster-critical`, unless `priorityClassName` is set to a priority
class other than `system-node-critical`, which then applies to them as well.

Some clusters limit the pods of the `system-cluster-critical` and
`system-node-critical` priority classes to a few namespaces through a
`ResourceQuota` admission configuration. There, the operator and webhook pods
only get admitted with a `ResourceQuota` in the operator namespace which allows
`system-cluster-critical`, and the daemon pods with one which allows
`system-node-critical`. Alternatively, `priorityClassName` of the Helm chart
sets the class of the operator pods, and `scheduling.priorityClassName` of the
SPOD the one of the daemon and the webhook pods.

## Set the logging verbosity

The `verbosity` of the SPOD sets the log level of the daemon containers:

- `0` (default): the regular logs.
- `1`: verbose logs, for example every audit line the JSON enricher processes.
- `2`: additionally traces every exec event which the JSON enricher receives
  from BPF.

The API accepts values up to `10`. Levels above `2` only add the debug logs of
the libraries the operator uses, like the Kubernetes client. To switch to the
verbose logs, patch the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"verbosity":1}}'
```

The daemon logs the new verbosity once at its start, so `--tail=-1` reads the
whole log instead of its last lines:

```console
$ kubectl -n security-profiles-operator logs --selector name=spod -c security-profiles-operator --tail=-1 | grep "Set logging verbosity"
"Set logging verbosity" verbosity=1
```

The `verbosity` of the SPOD and of the Helm chart only applies to the daemon.
The operator pods read the `SPO_VERBOSITY` environment variable of their
Deployment instead, see
[environment variables](#environment-variables-of-the-operator).

## Pull images from a private registry

The daemon and the webhook pods can pull their images from a private registry
with the `imagePullSecrets` of the SPOD. They reference secrets in the operator
namespace, for example a secret named `my-registry-secret` created with
`kubectl create secret docker-registry`:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"imagePullSecrets":[{"name":"my-registry-secret"}]}}'
```

The secrets of the operator pods themselves are part of the operator
Deployment, which the `imagePullSecrets` value of the Helm chart sets together
with the SPOD field.

## Configure the SELinux type

The operator uses the `spc_t` SELinux type in the security context of the
daemon pods by default. Patch the SPOD to use a different type:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"selinux":{"typeTag":"unconfined_t"}}}'
```

The type is ignored while AppArmor support is enabled through `enableAppArmor`,
which the operator reports with an `IgnoredSelinuxTypeTag` warning event on the
SPOD. Otherwise the operator updates the `spod` DaemonSet with the new SELinux
type, which recreates all daemon pods:

```console
$ kubectl -n security-profiles-operator get ds spod -o yaml | grep unconfined_t -B2
          runAsUser: 65535
          seLinuxOptions:
            type: unconfined_t
--
          runAsUser: 0
          seLinuxOptions:
            type: unconfined_t
--
          runAsUser: 0
          seLinuxOptions:
            type: unconfined_t
```

## Configure SELinux support

Besides `selinux.enable` and `selinux.typeTag`, the `selinux` section of the
SPOD provides the following settings:

- `enableRawSelinuxProfiles` (default `true`): set it to `false` to not start
  the `RawSelinuxProfile` controller.
- `customTemplatesConfigMap`: the name of a ConfigMap in the operator namespace
  containing `.cil` files which replace the templates bundled with selinuxd.
  This is useful on distributions like Flatcar Linux, whose SELinux policy base
  is incompatible with the bundled templates. Changes to the ConfigMap contents
  require restarting the daemon pods.
- `options`: restrictions for the `SelinuxProfile` objects, see the
  [SELinux profile](profiles.md#selinux-profiles) section.

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"selinux":{"enableRawSelinuxProfiles":false,"customTemplatesConfigMap":"my-templates"}}}'
```

### Select the selinuxd image

The selinuxd container has to match the SELinux policy of the nodes. The
`selinuxd-image-mapping.json` key of the `security-profiles-operator-profile`
ConfigMap maps regular expressions on the operating system of a node, as
`kubectl get node -o jsonpath='{.status.nodeInfo.osImage}'` shows it, to the
environment variables of the operator deployment which hold the images, like
`RELATED_IMAGE_SELINUXD_EL9`. The first matching entry wins, and a node without
a match gets the image of `RELATED_IMAGE_SELINUXD`, like a node whose variable
is not set. The
[command line reference](reference/security-profiles-operator.md) lists the
variables.

The operator picks a single image for all daemon pods: it matches the operating
system of the node which the operator pod runs on, when the operator starts. The
nodes with SELinux enabled should therefore run the operating system version of
the node of the operator pod. Changes to the mapping take effect when the
operator restarts.

The released manifests and the Helm chart set the variables of the images
which [selinuxd](https://github.com/containers/selinuxd) publishes. The mapping
also refers to `RELATED_IMAGE_SELINUXD_EL10` for RHEL 10 and CoreOS 10 nodes,
which selinuxd publishes no image for. Without setting it to an image built for
those nodes, they get the image of `RELATED_IMAGE_SELINUXD`.

For a mirrored registry in an air-gapped cluster, set the variables of the
operator deployment to the mirrored images, with the `selinuxdImage.*` values
for an installation with Helm. To support another operating
system, add an entry to the mapping, which refers to a variable the deployment
sets.

## Customize the daemon resource requirements

`daemonResourceRequirements` of the SPOD replaces the resource requirements of
the `security-profiles-operator` container of the daemon pods. The other
containers, like the log enricher or selinuxd, keep theirs. The field replaces
the whole default, which requests `64Mi` of memory, `100m` of CPU and `50Mi` of
ephemeral storage, and limits memory to `128Mi` and ephemeral storage to
`200Mi`. Repeat the defaults you want to keep, like the ephemeral storage:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"daemonResourceRequirements":{"requests":{"memory":"256Mi","cpu":"250m","ephemeral-storage":"50Mi"},"limits":{"memory":"512Mi","ephemeral-storage":"200Mi"}}}}'
```

The Helm chart sets the field through its `daemon.resources` value.

## Configure the rollout of the daemon

The operator replaces all daemon pods at once when the `spod` DaemonSet
changes, for example on an upgrade or a configuration change. To keep the
daemons of the other nodes running during a rollout, limit the number or the
percentage of daemon pods which can be unavailable at the same time through
`daemonUpdateStrategy.maxUnavailable`, like in the rolling update of a
DaemonSet:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"daemonUpdateStrategy":{"maxUnavailable":"25%"}}}'
```

It has to be at least `1` or `1%`, and it defaults to `100%`. A lower value
makes rollouts slower, but a daemon pod which cannot start, for example because
of a broken node, only stops the rollout instead of the daemons on all nodes.

## Restrict the allowed syscalls in seccomp profiles

The operator doesn't restrict the allowed syscalls in the seccomp profiles by
default, so a seccomp profile installed through the operator can allow any
syscall. To change that, define the list of allowed syscalls in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"security":{"allowedSyscalls": ["exit", "exit_group", "futex", "nanosleep"]}}}'
```

From then on, the operator only installs the seccomp profiles whose syscalls
are a subset of the allowed list, and rejects all others.

Every time the allow lists (`allowedSyscalls` or `allowedSeccompActions`)
change in the SPOD, the manager checks the existing profiles once for the
cluster, merged with their base profiles, and deletes the ones which are not
compliant. Profiles built on OCI base profiles, which only the daemons pull, are
not deleted: the daemons reject them on every node and report a
`ProfileNotAllowed` event instead, until the profile or the allow lists change.
The manager records the allow lists it enforced in the
`spo.x-k8s.io/enforced-allow-list-hash` annotation of the SPOD, so that a
restart of the operator does not delete the profiles created since then. The
daemons reject those without deleting them. A SPOD without the annotation, like
one written by an earlier operator version, gets its allow lists enforced once.

By default, the syscalls of all rules using the actions `SCMP_ACT_ALLOW`,
`SCMP_ACT_LOG`, `SCMP_ACT_TRACE` and `SCMP_ACT_NOTIFY` are checked against the
allowed list, and profiles using one of these actions as `defaultAction` are
rejected. The checked actions can be limited to a subset of them by using
`security.allowedSeccompActions`:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"security":{"allowedSeccompActions": ["SCMP_ACT_ALLOW"]}}}'
```

The API rejects other values than these four actions. A SPOD stored before the
API validated the field may still hold one: the manager then deletes no
profiles, the daemons reject all profiles, and the SPOD gets an
`InvalidSeccompSPODConfig` warning event until the value gets fixed.

## Constrain the scheduling of the daemon

`scheduling.tolerations` and `scheduling.affinity` of the SPOD constrain the
nodes of the daemon pods:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"scheduling":{"tolerations": [{...}]}}}'
```

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"scheduling":{"affinity": {...}}}}'
```

The Helm chart sets them through the `daemon.tolerations` and `daemon.affinity`
values. Without `tolerations`, the daemon tolerates the `NoSchedule` taints of
control plane nodes and the `NoExecute` taint of nodes which are not ready. An
empty list tolerates no taint.

The webhook deployment uses the `scheduling.tolerations` of the SPOD as well,
unless `webhook.tolerations` sets its own list:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"webhook":{"tolerations": [{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}]}}}'
```

## Select the log enricher source

The log enricher reads the audit events from the `auditd` or `syslog` files of
the node by default. On nodes without them, `enricher.logEnricherSource`
switches the source to `Bpf`, which reads the AppArmor audit events directly
from the kernel. It needs Linux 5.19 or later and only reports AppArmor events,
so it does not work for recording seccomp or SELinux profiles. The valid values
are `Auditd` (default) and `Bpf`:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge -p \
  '{"spec":{"enricher":{"enableLogEnricher":true,"logEnricherSource":"Bpf"}}}'
```

See [the log enricher](recording.md#log-enricher) for the log enricher itself.

## Enable memory optimization in the daemon

The daemon caches the pods running on its node. On nodes with many pods, this
cache can make the daemon use a lot of memory or run out of it.

The daemon can be configured to cache only the pods of its node which are
explicitly labeled for profile recording, by enabling memory optimization:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableMemoryOptimization":true}}'
```

A pod to record then needs the `spo.x-k8s.io/enable-recording: "true"` label,
other pods don't get recorded:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-recording-pod
  labels:
    spo.x-k8s.io/enable-recording: "true"
```

## Use a custom `/proc` location for nested environments like `kind`

The log enricher, the BPF recorder and the JSON enricher map processes to
containers through `/proc` of the host. In nested environments, like `kind`,
the host `/proc` can be mounted elsewhere. `hostProcVolumePath` of the SPOD
sets its location, which has to be `/proc` or a directory below it, for
example `/proc/host`:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"hostProcVolumePath":"/proc/host"}}'
```

The path only gets mounted while one of these features is enabled.

## Configure the concurrent reconciles of the manager

The manager runs its pod driven controllers (node status, binding tracker,
recording tracker and workload annotator) with 4 concurrent reconciles each.
Large clusters with many profiles or pods can raise this with the
`SPO_MAX_CONCURRENT_RECONCILES` environment variable of the operator, or the
`--max-concurrent-reconciles` flag of its `manager` command, see
[environment variables](#environment-variables-of-the-operator). For example
for the release manifests:

```shell
kubectl -n security-profiles-operator set env deploy/security-profiles-operator SPO_MAX_CONCURRENT_RECONCILES=8
```

Values below 1 fall back to the default.

## Configure the API server rate limit of the manager

The manager does not limit its requests to the API server on the client side,
it relies on
[API priority and fairness](https://kubernetes.io/docs/concepts/cluster-administration/flow-control/)
of the API server instead. To limit them, set the `SPO_KUBE_API_QPS` environment
variable of the operator, and optionally `SPO_KUBE_API_BURST`, see
[environment variables](#environment-variables-of-the-operator). The
`--kube-api-qps` and `--kube-api-burst` flags of the `manager` command do the
same. For example for the release manifests:

```shell
kubectl -n security-profiles-operator set env deploy/security-profiles-operator SPO_KUBE_API_QPS=50 SPO_KUBE_API_BURST=100
```

The burst only applies together with the queries per second and defaults to
the one of client-go.

The manager caches the profiles, their node statuses and the pods of the whole
cluster, so its memory usage grows with the cluster. Raise the memory limit of
the deployment, or the `resources` value of the Helm chart, if the manager runs
out of memory in a large cluster.

## Restrict the operator to namespaces

The Security Profiles Operator can optionally be restricted to a list of
namespaces. The profiles are cluster scoped and not affected by this, but the
namespaced resources, like `ProfileBinding` and `ProfileRecording` objects and
the pods they select, are only watched in these namespaces. The
`RESTRICT_TO_NAMESPACE` environment variable of the operator takes them as a
comma separated list, the operator namespace is always included. Without it,
the operator uses `WATCH_NAMESPACE`, which OLM sets.

### Restrict the operator with the release manifests

The `namespace-operator.yaml` manifest sets `RESTRICT_TO_NAMESPACE` to the
namespace of your choice:

```shell
NAMESPACE=<your-namespace>
curl -sSfL https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/namespace-operator.yaml |
  sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
```

The Helm chart sets the variable through its `restrictToNamespace` value.

### Restrict the operator when installing using OLM

With OLM, set the target namespaces in the `OperatorGroup` of the operator
namespace. OLM passes them to the operator through `WATCH_NAMESPACE`:

```yaml
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: security-profiles-operator
  namespace: security-profiles-operator
spec:
  targetNamespaces:
    - <your-namespace>
```

Alternatively, set `RESTRICT_TO_NAMESPACE` in `spec.config.env` of the
`Subscription`, see [environment variables](#environment-variables-of-the-operator),
which takes precedence over the target namespaces.

### OLM install modes and namespaces

The binding webhook never applies `ProfileBinding`s in the namespace of the
operator, so that no binding can change the profiles of the operator itself.
With the `OwnNamespace` install mode, which only targets that namespace,
`ProfileBinding`s therefore have no effect. Use the `SingleNamespace` or
`MultiNamespace` install mode to target other namespaces for them.
`ProfileRecording`s work in the namespace of the operator.

The operator and its daemons only watch the target namespaces of the install
mode, like with [restricted namespaces](#restrict-the-operator-to-namespaces).
The profiles are cluster scoped and not affected. The webhooks are not
restricted to the target namespaces, so only these should carry the
`spo.x-k8s.io/enable-binding` and `spo.x-k8s.io/enable-recording` labels: a
`ProfileBinding` or `ProfileRecording` in another namespace still changes the
pods there, but the operator and the daemons ignore it and its pods.

The bundle binds the `spo-metrics-client` cluster role to the
`spo-metrics-client` service account of the `security-profiles-operator`
namespace, and OLM creates that `ClusterRoleBinding` as it is. When OLM
installs the operator into another namespace, the service account there gets
no access to the metrics, which also breaks the automatically deployed
`ServiceMonitor`. Bind the cluster role to it yourself:

```shell
kubectl create clusterrolebinding spo-metrics-client-<your-namespace> \
  --clusterrole spo-metrics-client \
  --serviceaccount <your-namespace>:spo-metrics-client
```

## Configure the webhooks

Both profile binding and profile recording use webhooks. The operator manages
their configuration, the `spo-mutating-webhook-configuration` and
`spo-validating-webhook-configuration` objects. The `kubectl` manifests only
ship them empty, so that deleting the manifests removes them, and the operator
fills them in. The mutating webhooks are `binding.spo.io`, `recording.spo.io`,
`execmetadata.spo.io` and `nodedebuggingpod.spo.io`.

The binding and recording webhooks do nothing unless a `ProfileBinding` or
`ProfileRecording` exists in a namespace which is labeled with
`spo.x-k8s.io/enable-binding` or `spo.x-k8s.io/enable-recording`. The defaults
fit most clusters, but `webhook.options` of the SPOD can set the
`failurePolicy`, `namespaceSelector` and `objectSelector` of each webhook, to
restrict them to a subset of namespaces and objects, so that a bug in the
webhooks does not affect the others.

The binding and recording webhooks use the `Fail` failure policy by default,
so the API server rejects the pods they match while the webhook is
unavailable. With `failurePolicy: Ignore`, these pods get admitted without
their bound profile or without getting recorded instead.

A `namespaceSelector` or `objectSelector` in `webhook.options` replaces the
default selector of the webhook instead of adding to it. A `namespaceSelector`
for `binding.spo.io` or `recording.spo.io` therefore has to repeat the
`spo.x-k8s.io/enable-binding` or `spo.x-k8s.io/enable-recording` requirement,
otherwise the webhook applies to every namespace the selector matches. A
`namespaceSelector` for `execmetadata.spo.io` replaces the default one which
excludes the `kube-system`, `kube-public` and `kube-node-lease` namespaces and
the operator namespace, so repeat these exclusions in it. Whatever the
selector says, the operator keeps its own namespace excluded from
`binding.spo.io`, and the pods of the operator and the webhook excluded from
`recording.spo.io`.

`webhook.options` is a list, so a `--type=merge` patch replaces all of its
entries. The OpenShift manifests of this repository, `deploy/openshift-dev.yaml`
and `deploy/openshift-downstream.yaml`, default it to an entry which selects
the `debug.openshift.io/managed-by: oc-debug` label of `oc debug node` for
`nodedebuggingpod.spo.io`, instead of the
`app.kubernetes.io/managed-by: kubectl-debug` label of `kubectl debug node`.
Keep that entry when patching the options of an installation from these
manifests, an installation through OLM does not set it:

```yaml
      - name: nodedebuggingpod.spo.io
        objectSelector:
          matchLabels:
            debug.openshift.io/managed-by: oc-debug
```

For example, to set the `binding.spo.io` webhook's configuration to ignore
errors as well as restrict it to the namespaces labeled with
`spo.x-k8s.io/enable-binding` which are also labeled with
`spo.x-k8s.io/bind-here=true`, create the following patch file
`/tmp/spod-wh.patch`:

```yaml
spec:
  webhook:
    options:
      - name: binding.spo.io
        failurePolicy: Ignore
        namespaceSelector:
          matchExpressions:
            - key: spo.x-k8s.io/enable-binding
              operator: Exists
            - key: spo.x-k8s.io/bind-here
              operator: In
              values:
                - "true"
```

And patch the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --patch-file /tmp/spod-wh.patch --type=merge
```

The remaining fields of the webhooks, like `timeoutSeconds` and `rules`, are
owned by the operator, which reverts manual changes to them. Configure the
webhooks only through `webhook.options`.

To view the resulting `MutatingWebhookConfiguration`, call:

```shell
kubectl get MutatingWebhookConfiguration spo-mutating-webhook-configuration -oyaml
```

The webhook configuration and its related resources can also be deployed
statically, for example by using the `deploy/webhook-operator.yaml` manifest,
which runs the operator with `--webhook=false`. In this case, the operator sets
`webhook.staticConfig` to `true` in the SPOD it creates, and does not create or
update the webhook configuration and its related resources, so
`webhook.options` do not apply either. Its MutatingWebhookConfiguration only
registers the `binding.spo.io` and `recording.spo.io` webhooks. The
`execmetadata.spo.io` and `nodedebuggingpod.spo.io` webhooks of the JSON
enricher below are not part of it, add them to the static configuration to use
them.

The exec metadata and node debugging pod webhooks work together with the JSON
enricher. They are enabled only when the JSON enricher is enabled, and
`spec.enricher.enableExecMetadata: false` removes both of them, for example for
images without an `env` binary. See the
[audit logging guide](audit-logging-guide.md) for the JSON enricher.

Next to the mutating webhooks, the operator manages the
`spo-validating-webhook-configuration` `ValidatingWebhookConfiguration`. Its
`rawselinuxprofile-validation.spo.io` webhook rejects `RawSelinuxProfile`
objects with CIL statements which would affect the whole node instead of the
profile, like `class`, `role` or `typepermissive`. It uses the `Fail` failure
policy and cannot be configured with `webhook.options`. Its match condition
only sends the creations and the updates which change the policy to it, so that
finalizers and labels can still be updated while the webhook is not reachable.
The `binding-image.spo.io` webhook of the same configuration rejects image
changes of running pods which a profile binding matches, see
[the profile bindings](profiles.md#binding-precedence-and-status). It takes the
`webhook.options` of `binding.spo.io`, so that it selects the same namespaces
and pods.

## Customize the admission policies of the `spod` service account

The operator creates the `spo-spod-*` ValidatingAdmissionPolicies and their
bindings if they are missing, see the
[security model](security-model.md#spod). It updates only the ones it created,
which carry the `spo.x-k8s.io/admission-policy-hash` annotation. To change a
policy or binding, for example to only audit the requests of a binding,
replace it with an own copy without that annotation, which the operator leaves
alone:

```shell
kubectl get validatingadmissionpolicybinding spo-spod-jobs -o yaml >binding.yaml
# Remove the spo.x-k8s.io/admission-policy-hash annotation and change the spec.
kubectl replace -f binding.yaml
```

Deleting a policy or binding does not turn it off, the operator creates it
again.
