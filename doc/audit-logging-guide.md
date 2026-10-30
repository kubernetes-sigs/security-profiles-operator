# Audit logging

[Documentation](README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Profiles](profiles.md) | [Recording](recording.md) | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

The JSON enricher of the Security Profiles Operator audits the activity in
pods. Like the [log enricher](recording.md#log-enricher), it reads the audit
events of the node from auditd (`/var/log/audit/audit.log`) or syslog
(`/var/log/syslog`), and writes an audit log in JSON lines format, similar to
the audit log of the Kubernetes API server. This is useful for:

- Seeing what users and automated processes are doing inside a pod.
- Tracking when someone uses commands like `kubectl exec` to get into a
  running container and run commands or scripts.
- Monitoring activities in debug containers where users might run various
  tools.

The audit events come from a seccomp profile which logs the syscalls to
audit, for example `execve`, which the pods get through their security context
or a [ProfileBinding](profiles.md#bind-workloads-to-profiles). The
[walkthrough](#walkthrough) at the end of this page sets up the whole chain.

<!-- toc -->
- [Enable the JSON enricher](#enable-the-json-enricher)
- [Output format](#output-format)
- [Configure the JSON enricher](#configure-the-json-enricher)
  - [Audit log interval](#audit-log-interval)
  - [Write the audit log to a file](#write-the-audit-log-to-a-file)
  - [Rotate the audit log file](#rotate-the-audit-log-file)
  - [Verbosity](#verbosity)
  - [Filters](#filters)
- [Attribute exec sessions and node debugging](#attribute-exec-sessions-and-node-debugging)
  - [Exec sessions](#exec-sessions)
  - [Node debugging sessions](#node-debugging-sessions)
  - [Limit the webhooks to some namespaces](#limit-the-webhooks-to-some-namespaces)
- [Walkthrough](#walkthrough)
  - [Step 1: Install the operator](#step-1-install-the-operator)
  - [Step 2: Mount a directory for the audit log](#step-2-mount-a-directory-for-the-audit-log)
  - [Step 3: Enable the JSON enricher and its filters](#step-3-enable-the-json-enricher-and-its-filters)
  - [Step 4: Create a seccomp profile](#step-4-create-a-seccomp-profile)
  - [Step 5: Bind the profile to the pods of a namespace](#step-5-bind-the-profile-to-the-pods-of-a-namespace)
  - [Step 6: Audit an exec session](#step-6-audit-an-exec-session)
  - [Step 7: Audit a node debugging session](#step-7-audit-a-node-debugging-session)
  - [Step 8: Correlate with the API server audit log](#step-8-correlate-with-the-api-server-audit-log)
<!-- /toc -->

## Enable the JSON enricher

Enable the JSON enricher in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true}}}'
```

Alternatively, set the `ENABLE_JSON_ENRICHER` environment variable of the
operator Deployment to `true`, for example through the `spec.config.env` of
the `Subscription` of an OLM installation.

The operator then rolls out the `spod` DaemonSet with the `json-enricher`
container. Like the log enricher, it runs as root in the host PID namespace,
see the [security model](security-model.md). It also deploys the
`execmetadata.spo.io` and `nodedebuggingpod.spo.io` webhooks, see
[Attribute exec sessions and node debugging](#attribute-exec-sessions-and-node-debugging).

While processing the audit events, the enricher reads the details of the
process from `/proc/<pid>`. A short lived process may be gone before that, so
the enricher also collects the details of new processes with eBPF and falls
back to them.

## Output format

Each JSON line describes the syscalls of one process within the
[audit log interval](#audit-log-interval), for example:

```json
{"auditID":"8b9a4b6c-3f9e-4a8c-9d0e-2b1f3c4d5e6f","cmdLine":"touch demo-file","executable":"/usr/bin/touch","gid":0,"node":{"name":"worker-0"},"pid":12345,"requestUID":"d1c3a5e7-1f2b-4c6d-8e9f-0a1b2c3d4e5f","resource":{"container":"my-nginx-pod","namespace":"default","pod":"my-nginx-pod"},"syscalls":["execve"],"timestamp":"2025-05-07T09:55:40.574Z","uid":0,"version":"spo/v1_alpha"}
```

The fields are:

- `version`: the version of the log format, `spo/v1_alpha`.
- `auditID`: a unique ID of the line.
- `timestamp`: when the activity happened, in ISO 8601 format and UTC.
- `executable`: the program that was run, like `/usr/bin/bash`.
- `cmdLine`: the command line of the process, like `ls -l /home`.
- `pid`: the process ID on the node.
- `uid` and `gid`: the user and group ID which ran the process. They are left
  out if the audit event does not carry them.
- `syscalls`: the syscalls the process made, sorted and without duplicates.
- `resource`: the `pod`, `namespace` and `container` of the process, or `null`
  if the enricher could not resolve the container.
- `node`: the `name` of the node.
- `requestUID`: the UID of the `kubectl exec` or node debugging request which
  started the process, if there is one, see
  [Attribute exec sessions and node debugging](#attribute-exec-sessions-and-node-debugging).

## Configure the JSON enricher

The options of the JSON enricher are fields of
`spec.enricher.jsonEnricherOptions` of the SPOD.

### Audit log interval

`auditLogIntervalSeconds` sets how often the enricher writes the audit log.
The syscalls of each process within the interval are grouped into one line.
The default is 60 seconds and the minimum 1. For example, to write the audit
log every 30 seconds:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogIntervalSeconds":30}}}}'
```

### Write the audit log to a file

By default, the audit log goes to the standard output of the `json-enricher`
container:

```shell
kubectl -n security-profiles-operator logs --since=1m --selector name=spod -c json-enricher --max-log-requests 6 -f
```

To write it to a file instead, the file has to be below a volume mounted into
the container, because the container has a read-only root filesystem, and an
`auditLogPath` outside of the volume keeps the JSON enricher from starting.
The release manifests and the Helm chart mount a 500Mi `emptyDir` at
`/data/logs/jsonenricher`, so a path like `/data/logs/jsonenricher/audit.log`
works without further changes, but its contents get lost with the pod. To
keep the file on the node, replace the volume with two keys of the
`security-profiles-operator-profile` ConfigMap:

- `json-enricher-log-volume-source.json`: the volume to store the log file
  in, as a JSON encoded `corev1.VolumeSource`, which holds the volume type
  fields of a
  [Volume](https://kubernetes.io/docs/reference/kubernetes-api/config-and-storage-resources/volume/)
  without its `name`.
- `json-enricher-log-volume-mount-path`: the directory in the container where
  the volume gets mounted.

For example, to mount the host directory `/tmp/logs`, save this patch as
`patch-volume-source.json`:

```json
{
  "data": {
    "json-enricher-log-volume-mount-path": "/tmp/logs",
    "json-enricher-log-volume-source.json": "{\"hostPath\": {\"path\": \"/tmp/logs\",\"type\": \"DirectoryOrCreate\"}}"
  }
}
```

and apply it:

```shell
kubectl patch configmap security-profiles-operator-profile -n security-profiles-operator --patch-file patch-volume-source.json
```

Applying the release manifest again or a `helm upgrade` resets both keys to
the `emptyDir` at `/data/logs/jsonenricher`, so patch them again afterwards,
or set an `auditLogPath` below that directory before the upgrade.

The operator watches this ConfigMap, so no restart is needed. While the JSON
enricher is enabled, a change of the ConfigMap rolls out the `spod` DaemonSet
with the new volume.

Then set the full path of the audit log file in `auditLogPath`:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogPath":"/tmp/logs/audit1.log"}}}}'
```

Each node writes the audit log of its pods to its own file. To read it, find
the node of a pod with `kubectl get pod <pod> -o wide`, then log into the node
or start a node debugging session and read the file, here
`/tmp/logs/audit1.log`, which a node debugging session finds below `/host`
at `/host/tmp/logs/audit1.log`.

### Rotate the audit log file

The enricher rotates the audit log file. These options are similar to the
[log settings of the Kubernetes API server](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/):

- `auditLogMaxSize`: the maximum size in megabytes of the log file before it
  gets rotated. The default is 100 MB.
- `auditLogMaxBackups`: the maximum number of rotated log files to keep. If
  neither `auditLogMaxBackups` nor `auditLogMaxAge` is set, or both are 0, the
  enricher keeps 10 rotated files. With `auditLogMaxAge` set, 0 or no value
  keeps any number of files within that age.
- `auditLogMaxAge`: the maximum number of days to keep rotated log files. By
  default, rotated files are not removed based on their age.

For example:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogPath":"/tmp/logs/audit1.log","auditLogMaxSize":500,"auditLogMaxBackups":2,"auditLogMaxAge":10}}}}'
```

### Verbosity

The `spec.verbosity` of the SPOD applies to the JSON enricher too. With `1`,
it logs every audit line it processes, with `2` additionally every exec event
it receives from eBPF, see
[Set the logging verbosity](configuration.md#set-the-logging-verbosity).

### Filters

`spec.enricher.jsonEnricherFilters` selects the lines the JSON enricher logs,
for example only the ones of exec sessions, see
[Filter the enricher logs](recording.md#filter-the-enricher-logs). The nested
fields of the JSON lines are selected with a `/`, like `resource/namespace`.

## Attribute exec sessions and node debugging

By default, when you use `kubectl exec` to access a container, Kubernetes
doesn't pass the user's identity into the environment of that session. The
`uid` and `gid` of the JSON lines then belong to the user of the container,
which in most cases is root, and do not tell who started the session.

The JSON enricher therefore relies on two mutating webhooks,
`execmetadata.spo.io` and `nodedebuggingpod.spo.io`, which the operator
deploys together with it. They set the UID of the request which started the
session in the `SPO_EXEC_REQUEST_UID` environment variable of the session.
The webhook starts an exec session through an env command like
`env SPO_EXEC_REQUEST_UID=<uid> ls`, so the enricher takes the request UID of
an env command from the assignment which the webhook added to its arguments,
and the one of any other process from its environment, and writes it as
`requestUID`. The webhooks also add it as an audit annotation of the
request, which the API server writes to its audit log, if enabled, as
`execmetadata.spo.io/SPO_EXEC_REQUEST_UID` or
`nodedebuggingpod.spo.io/SPO_EXEC_REQUEST_UID`. The `requestUID` thereby links
the activity on the node to the API server audit log entry of the request,
which records who started it.

The attribution is best effort and not audit evidence. The workload controls
the environment of its processes: a pod author can set the variable on a
container, so that its processes carry a made-up request UID, and a process
in an exec session can unset or change it before it starts other programs, so
that their activity is not attributed to the exec request. If a container
already defines `SPO_EXEC_REQUEST_UID`, the webhook's value overrides it for
the exec session. Use the API server audit log as the record of who started
an exec session or a debug pod, and the `requestUID` only to correlate the
node activity with it.

`spec.enricher.enableExecMetadata` of the SPOD controls both webhooks and
defaults to `true`. It has no effect while the JSON enricher is disabled.

### Exec sessions

The `execmetadata.spo.io` webhook rewrites every `kubectl exec` to run through
the `env` binary of the container image, so that the session gets the
variable. Images without an `env` binary then fail to exec. Disable the
webhooks for such clusters:

```shell
kubectl -n security-profiles-operator patch spod spod --type merge \
  -p '{"spec":{"enricher":{"enableExecMetadata":false}}}'
```

The webhook also sets the variable in the ephemeral containers which
`kubectl debug <pod>` adds to a pod, when they get added. The environment of
ephemeral containers which exist already cannot change.

By default, `execmetadata.spo.io` applies to all namespaces except
`kube-system`, `kube-public`, `kube-node-lease` and the operator namespace.

### Node debugging sessions

`kubectl debug node/<node-name>` starts a debug pod on the node. The
`nodedebuggingpod.spo.io` webhook sets `SPO_EXEC_REQUEST_UID` in the debug
pods of all namespaces. It selects them by the label
`app.kubernetes.io/managed-by: kubectl-debug`, which `kubectl debug` adds to
them since [kubectl debug: add label for debugger pod](https://github.com/kubernetes/kubernetes/pull/131791),
so the node debugging sessions of an older client do not get a request UID.

Other clients label their debug pods differently, for example `oc debug` of
OpenShift uses `debug.openshift.io/managed-by: oc-debug`. Change the
`objectSelector` of the webhook in its `spec.webhook.options` entry of the
SPOD for them. Its `objectSelector` replaces the default one. A label selector
requires all of its labels, so the webhook then catches the pods of the new
selector instead of the ones of `kubectl debug`. For example, to catch
`oc debug` pods instead:

```yaml
spec:
  webhook:
    options:
      - name: nodedebuggingpod.spo.io
        objectSelector:
          matchLabels:
            debug.openshift.io/managed-by: oc-debug
```

The OpenShift manifests of this repository, `deploy/openshift-dev.yaml` and
`deploy/openshift-downstream.yaml`, already set this entry, an installation
through OLM does not, see
[Configure the webhooks](configuration.md#configure-the-webhooks).

### Limit the webhooks to some namespaces

The `namespaceSelector` of a webhook in its `spec.webhook.options` entry of
the SPOD selects the namespaces the webhook applies to. For
`execmetadata.spo.io` it replaces the default selector, including the
exclusion of `kube-system`, `kube-public`,
`kube-node-lease` and the operator namespace, so exclude them again in a
custom selector. For example, to apply `execmetadata.spo.io` only to the
namespaces labeled `audit: enabled`:

```yaml
spec:
  webhook:
    options:
      - name: execmetadata.spo.io
        namespaceSelector:
          matchExpressions:
            - key: audit
              operator: In
              values:
                - enabled
            - key: kubernetes.io/metadata.name
              operator: NotIn
              values:
                - kube-system
                - kube-public
                - kube-node-lease
                - security-profiles-operator
```

Edit the SPOD with `kubectl -n security-profiles-operator edit spod spod` to
add the entry, the operator then reconfigures the webhook.

## Walkthrough

This walkthrough sets up audit logging for exec and node debugging sessions.
It uses a single node cluster of
[hack/local-up-cluster.sh](https://github.com/kubernetes/kubernetes/blob/801ee44/hack/local-up-cluster.sh)
with the API server audit log enabled, but works on any cluster which meets
the [requirements](installation.md#requirements) of the operator. It involves
two personas:

- **Auditor**: configures the audit logging and reads the audit logs.
- **Cluster administrator**: performs administrative tasks such as exec into
  pods or debugging nodes, whose activities get audited.

### Step 1: Install the operator

Install the operator by following [Installation](installation.md).

### Step 2: Mount a directory for the audit log

Mount the host directory `/tmp/logs` into the JSON enricher as described in
[Write the audit log to a file](#write-the-audit-log-to-a-file).

### Step 3: Enable the JSON enricher and its filters

Patch the SPOD to enable the JSON enricher, write the audit log to
`/tmp/logs/audit1.log`, rotate it as described in
[Rotate the audit log file](#rotate-the-audit-log-file), and only log the
activity of exec and node debugging sessions with the filter of
[Filter examples](recording.md#filter-examples):

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"verbosity":0,"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogIntervalSeconds":20,"auditLogPath":"/tmp/logs/audit1.log","auditLogMaxSize":500,"auditLogMaxBackups":2,"auditLogMaxAge":10}, "jsonEnricherFilters":"[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]"}}}'
```

### Step 4: Create a seccomp profile

This profile allows all syscalls and logs the ones which start processes.
Create a file named `profile1.yaml`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
    - action: SCMP_ACT_LOG
      names:
        - execve
        - execveat
        - clone
        - fork
```

Apply the profile:

```shell
kubectl apply -f profile1.yaml
```

### Step 5: Bind the profile to the pods of a namespace

A `"*"` binding applies the profile to all new pods of the `default`
namespace. Create a file named `profile1-binding.yaml`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  namespace: default
  name: all-pod-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile1
  image: "*"
```

Apply the binding and label the namespace to activate it:

```shell
kubectl apply -f profile1-binding.yaml
kubectl label ns default spo.x-k8s.io/enable-binding=
```

Instead of the binding, a pod can also set the profile in its security
context, with `localhostProfile: operator/profile1.json`, see
[Use a seccomp profile](profiles.md#use-a-seccomp-profile).

### Step 6: Audit an exec session

Create a test pod:

```shell
kubectl run my-nginx-pod --image=nginx --restart=Never
```

Exec into the pod and run a command:

```console
$ kubectl exec -it my-nginx-pod -- /bin/sh
# touch demo-file
# exit
```

The audit log at `/tmp/logs/audit1.log` on the node of the pod gets a JSON
line for the `touch` command, with a `requestUID`.

### Step 7: Audit a node debugging session

Debug the node, where `my-node` is its name. The debug pod runs in the
`default` namespace, so it gets the profile of the binding:

```console
$ kubectl debug node/my-node -it --image=ubuntu -- bash
root@my-node:/# touch demonodedebug
root@my-node:/# exit
```

The activity gets logged to the same file.

Privileged containers run without a seccomp profile, so the activity of a
privileged debug pod, like the one of `kubectl debug --profile=sysadmin`, does
not get audited. CRI-O can apply a seccomp profile to privileged containers
with the `privileged_seccomp_profile` option of its `[crio.runtime]`
configuration, or its `--privileged-seccomp-profile` flag, which takes the path
of the profile file on the node:

```toml
[crio.runtime]
privileged_seccomp_profile = "/var/lib/kubelet/seccomp/operator/profile1.json"
```

### Step 8: Correlate with the API server audit log

Look up the `requestUID` of a JSON line in the audit log of the API server,
whose entry records who started the session. `hack/local-up-cluster.sh`
writes it to `/tmp/kube-apiserver-audit.log`:

```shell
grep <requestUID> /tmp/kube-apiserver-audit.log
```

The `requestUID` comes from an environment variable of the audited process,
which the workload can set or unset, so it is a best effort hint and not
audit evidence, see
[Attribute exec sessions and node debugging](#attribute-exec-sessions-and-node-debugging).
