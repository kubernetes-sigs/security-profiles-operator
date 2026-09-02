[Installation and Usage](installation-usage.md) | [Installation](installation.md) | **Profiles** | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Create and Install Security Profiles](#create-and-install-security-profiles)
  - [Seccomp profile](#seccomp-profile)
    - [Record Seccomp profile](#record-seccomp-profile)
      - [Recording based on audit log](#recording-based-on-audit-log)
      - [Recording based on eBPF instrumentation](#recording-based-on-ebpf-instrumentation)
    - [Use Seccomp profile](#use-seccomp-profile)
  - [Audit JSON log enricher](#audit-json-log-enricher)
    - [Audit JSON Log Enricher Configuration](#audit-json-log-enricher-configuration)
      - [Audit Log Interval](#audit-log-interval)
      - [Audit Log File Destination](#audit-log-file-destination)
        - [Audit Log File Fine-Tuning (Rotation)](#audit-log-file-fine-tuning-rotation)
        - [Verbosity (Debugging Logs)](#verbosity-debugging-logs)
    - [How to Monitor Audit Logs for a Specific Pod](#how-to-monitor-audit-logs-for-a-specific-pod)
    - [Correlating with API Server Audit Log](#correlating-with-api-server-audit-log)
  - [AppArmor Profile](#apparmor-profile)
    - [Record AppArmor profile](#record-apparmor-profile)
    - [Use AppArmor profile](#use-apparmor-profile)
  - [SELinux profile](#selinux-profile)
    - [Record SELinux profile](#record-selinux-profile)
    - [Use SELinux profile](#use-selinux-profile)
  - [Filtering Logs](#filtering-logs)
    - [Rule Evaluation Logic](#rule-evaluation-logic)
    - [Examples](#examples)
  - [General Considerations](#general-considerations)
    - [Base syscalls for a container runtime](#base-syscalls-for-a-container-runtime)
    - [Recording profiles without applying them](#recording-profiles-without-applying-them)
    - [Disable profile recording](#disable-profile-recording)
    - [OCI Artifact support for base profiles](#oci-artifact-support-for-base-profiles)
    - [Bind workloads to profiles with ProfileBindings](#bind-workloads-to-profiles-with-profilebindings)
    - [Merging per-container profile instances](#merging-per-container-profile-instances)
<!-- /toc -->

## Create and Install Security Profiles

The next sections will describe how to record and install security profiles for a container. The namespace
where the recording takes place needs to be labeled with `spo.x-k8s.io/enable-recording` in order to enable
recording in that namespace, as following:

```sh
$ kubectl label ns spo-test spo.x-k8s.io/enable-recording=
```

Note that the label value is not important, only its presence matters.

### Seccomp profile

#### Record Seccomp profile

The operator is capable of recording seccomp profiles by the usage of the
built-in [eBPF](https://ebpf.io) recorder or by evaluating the [audit][auditd] or [syslog][syslog] files. Each method has
its pros and cons as well as separate technical requirements.

##### Recording based on audit log

The operator ships with a log enrichment feature, which is disabled per
default. The reason for that is that the log enricher container runs in
privileged mode to be able to read the audit logs from the local node. It is also
required that the enricher is able to read the host processes and therefore runs
within host PID namespace (`hostPID`).

One of the following requirements to the Kubernetes node have to be fulfilled to
use the log enrichment feature:

- [auditd][auditd] needs to run and has to be configured to log into
  `/var/log/audit/audit.log`
- [syslog][syslog] can be used as fallback to auditd and needs to log into
  `/var/log/syslog`. Depending on the system configuration, a printk rate limiting may be
  in place which has direct influence on the log enrichment. To disable the rate
  limiting, set the following sysctls:
  ```
  > sysctl -w kernel.printk_ratelimit=0
  > sysctl -w kernel.printk_ratelimit_burst=0
  ```

[auditd]: https://man7.org/linux/man-pages/man8/auditd.8.html
[syslog]: https://man7.org/linux/man-pages/man3/syslog.3.html

If all requirements are met, then the feature can be enabled by patching the
`spod` configuration:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher":true}}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

Alternatively, make sure the operator deployment sets the `ENABLE_LOG_ENRICHER` variable,
to `true`, either by setting the environment variable in the deployment or by enabling
the variable through a `Subscription` resource, when installing the operator using OLM.
See [Constrain spod scheduling](installation.md#constrain-spod-scheduling) for an example of
setting `tolerations` and `affinity` on the SPOD.

Now the operator will take care of re-deploying the `spod` DaemonSet and the
enricher should be listening for new changes to the audit logs:

```
> kubectl -n security-profiles-operator logs -f ds/spod log-enricher
I0623 12:51:04.257814 1854764 deleg.go:130] setup "msg"="starting component: log-enricher"  "buildDate"="1980-01-01T00:00:00Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.16.2" "platform"="linux/amd64" "version"="0.4.0-dev"
I0623 12:51:04.257890 1854764 enricher.go:44] log-enricher "msg"="Starting log-enricher on node: 127.0.0.1"
I0623 12:51:04.257898 1854764 enricher.go:46] log-enricher "msg"="Connecting to local GRPC server"
I0623 12:51:04.258061 1854764 enricher.go:69] log-enricher "msg"="Reading from file /var/log/audit/audit.log"
2021/06/23 12:51:04 Sought /var/log/audit/audit.log - &{Offset:0 Whence:2}
```

To record by using the log enricher, create a `ProfileRecording` which is using
`recorder: Logs`:

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

Then we can create a workload to be recorded, for example two containers within
a single pod:

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

If the pod is up and running:

```
> kubectl get pods
NAME     READY   STATUS    RESTARTS   AGE
my-pod   2/2     Running   0          18s
```

Then the enricher should indicate that it receives audit logs for those containers:

```
> kubectl -n security-profiles-operator logs --since=1m --selector name=spod -c log-enricher
…
I0705 12:08:18.729660 1843190 enricher.go:136] log-enricher "msg"="audit"  "container"="redis" "executable"="/usr/local/bin/redis-server" "namespace"="default" "node"="127.0.0.1" "pid"=1847839 "pod"="my-pod" "syscallID"=232 "syscallName"="epoll_wait" "timestamp"="1625486870.273:187492" "type"="seccomp"
```

Now, if we remove the pod:

```
> kubectl delete pod my-pod
```

Then the operator will reconcile two seccomp profiles:

```
> kubectl get sp
NAME                   STATUS      AGE
test-recording-nginx   Installed   15s
test-recording-redis   Installed   15s
```

Please note that log based recording does not have any effect if the recorded container
is privileged, that is, the container's security context sets `privileged: true`. This
is because privileged containers are not subject to SELinux or seccomp policies at all
and the log based recording makes use of a special seccomp or SELinux profile respectively
to record the syscalls or SELinux events.

##### Recording based on eBPF instrumentation

The operator also supports an [eBPF](https://ebpf.io) based recorder. This
recorder only supports seccomp and AppArmor profiles for now. Recording via eBPF works for
kernels which expose the `/sys/kernel/btf/vmlinux` file per default. In
addition, this feature requires new library versions and thus might not be
enabled. You can find out if your SPO build has the eBPF feature disabled by
looking at the build tags:

```
> kubectl logs --selector name=security-profiles-operator | grep buildTags
```

If the output contains `no_bpf` then the feature has been disabled.

To use the recorder, enable it by patching the `spod` configuration:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableBpfRecorder":true}}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

Alternatively, make sure the operator deployment sets the `ENABLE_BPF_RECORDER`
environment variable to `true`. This method can be easier to set up during
installation than patching the `spod`.

We can verify that the recorder is up and running after the spod rollout has
been finished:

```
> kubectl -n security-profiles-operator logs --selector name=spod -c bpf-recorder
Found 6 pods, using pod/spod-h7dpm
I1115 12:02:45.991786  110307 main.go:182]  "msg"="Set logging verbosity to 0"
I1115 12:02:45.991901  110307 deleg.go:130] setup "msg"="starting component: bpf-recorder"  "buildDate"="1980-01-01T00:00:00Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.16.9" "libseccomp"="2.5.1" "platform"="linux/amd64" "version"="0.4.0-dev"
I1115 12:02:45.991955  110307 bpfrecorder.go:105] bpf-recorder "msg"="Setting up caches with expiry of 1h0m0s"
I1115 12:02:45.991973  110307 bpfrecorder.go:121] bpf-recorder "msg"="Starting log-enricher on node: ip-10-0-228-234.us-east-2.compute.internal"
I1115 12:02:45.994232  110307 bpfrecorder.go:152] bpf-recorder "msg"="Connecting to metrics server"
I1115 12:02:48.373469  110307 bpfrecorder.go:168] bpf-recorder "msg"="Got system mount namespace: 4026531840"
I1115 12:02:48.373518  110307 bpfrecorder.go:170] bpf-recorder "msg"="Doing BPF load/unload self-test"
I1115 12:02:48.373529  110307 bpfrecorder.go:336] bpf-recorder "msg"="Loading bpf module"
I1115 12:02:48.373570  110307 bpfrecorder.go:403] bpf-recorder "msg"="Using system btf file"
I1115 12:02:48.373770  110307 bpfrecorder.go:356] bpf-recorder "msg"="Loading bpf object from module"
I1115 12:02:48.403766  110307 bpfrecorder.go:362] bpf-recorder "msg"="Getting bpf program sys_enter"
I1115 12:02:48.403792  110307 bpfrecorder.go:368] bpf-recorder "msg"="Attaching bpf tracepoint"
I1115 12:02:48.406205  110307 bpfrecorder.go:373] bpf-recorder "msg"="Getting syscalls map"
I1115 12:02:48.406287  110307 bpfrecorder.go:379] bpf-recorder "msg"="Getting comms map"
I1115 12:02:48.406862  110307 bpfrecorder.go:396] bpf-recorder "msg"="Module successfully loaded, watching for events"
I1115 12:02:48.406908  110307 bpfrecorder.go:677] bpf-recorder "msg"="Unloading bpf module"
I1115 12:02:48.411636  110307 bpfrecorder.go:176] bpf-recorder "msg"="Starting GRPC API server"
```

The recorder does a system sanity check on startup to ensure everything works as
expected. This includes a `load` and `unload` of the BPF module. If this fails,
please open an issue so that we can find out what went wrong.

To record seccomp profiles by using the BPF recorder, create a
`ProfileRecording` which is using `recorder: Bpf`:

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

Then we can create a workload to be recorded, for example this one:

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

If the pod is up and running:

```
> kubectl get pods
NAME     READY   STATUS    RESTARTS   AGE
my-pod   1/1     Running   0          10s
```

Then the BPF recorder should indicate that it found the container:

```
> kubectl -n security-profiles-operator logs --since=1m --selector name=spod -c bpf-recorder
…
I1115 12:12:30.029216   66106 bpfrecorder.go:654] bpf-recorder "msg"="Found container ID in cluster"  "containerID"="c2e10af47011f6a61cd7e92073db2711796f174af35b34486967588ef7f95fbc" "containerName"="nginx"
I1115 12:12:30.029264   66106 bpfrecorder.go:539] bpf-recorder "msg"="Saving PID for profile"  "mntns"=4026533352 "pid"=74384 "profile"="my-recording-nginx-1636978341"
I1115 12:12:30.029428   66106 bpfrecorder.go:512] bpf-recorder "msg"="Using short path via tracked mount namespace"  "mntns"=4026533352 "pid"=74403 "profile"="my-recording-nginx-1636978341"
I1115 12:12:30.029575   66106 bpfrecorder.go:512] bpf-recorder "msg"="Using short path via tracked mount namespace"  "mntns"=4026533352 "pid"=74402 "profile"="my-recording-nginx-1636978341"
…
```

Now, if we remove the pod:

```
> kubectl delete pod my-pod
```

Then the operator will reconcile the seccomp profile:

```
> kubectl get sp
NAME                 STATUS      AGE
my-recording-nginx   Installed   15s
```

#### Use Seccomp profile

Use the `SeccompProfile` kind to create profiles. Example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
```

This seccomp profile will be saved at the path:

`/var/lib/kubelet/seccomp/operator/profile1.json`.

An init container will set up the root directory of the operator to be able to
run it without root G/UID. This will be done by creating a symlink from the
rootless profile storage `/var/lib/security-profiles-operator` to the default seccomp root
path inside of the kubelet root `/var/lib/kubelet/seccomp/operator`.

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

You can find the profile path of the seccomp profile by checking the
`seccompProfile.localhostProfile` attribute (remember to use the `wide`
output mode):

```sh
$ kubectl get seccompprofile profile1 --output wide
NAME       STATUS   AGE   SECCOMPPROFILE.LOCALHOSTPROFILE
profile1   Active   14s   operator/profile1.json
```

You can apply the profile to an existing application, such as a Deployment or
DaemonSet:

```sh
kubectl --namespace my-namespace patch deployment myapp --patch '{"spec": {"template": {"spec": {"securityContext": {"seccompProfile": {"type": "Localhost", "localhostProfile": "'$(kubectl --namespace my-namespace get seccompprofile profile1 --output=jsonpath='{.status.seccompProfile\.localhostProfile}')'}}}}}}'
deployment.apps/myapp patched
```

The pods in the Deployment will be automatically restarted. Check that the
profile was applied correctly:

```sh
$ kubectl --namespace my-namespace get deployment myapp --output=jsonpath='{.spec.template.spec.securityContext}' | jq .
{
  "seccompProfile": {
    "localhostProfile": "operator/profile1.json",
    "type": "Localhost"
  }
}
```

Note that a security profile that is in use by existing pods cannot be
deleted unless the pods exit or are removed - the profile deletion is
protected by finalizers.

### Audit JSON log enricher

Similar to the log enricher feature above, audit JSON log enricher watches auditd (`/var/log/audit/audit.log`)
or the syslog (`/var/log/syslog`) and generates an audit log in JSON lines format. Each JSON line will include the
following:

- **Timestamp**: When the activity happened, shown in a standard ISO format
- **Executable Name**: The name of the program that was run (e.g., bash, ls).
- **Command Line Arguments (cmdline)**: The extra instructions given when the program was started (e.g., ls -l /home).
- **User and Group IDs (uid/gid)**: The identification numbers of the system user who ran the program.
- **System Calls (syscalls)**: A list of system calls (syscalls) that the process made

This log format and the configuration is similar to how Kubernetes itself records audit logs. This is useful for:

- Seeing what users and automated processes are doing inside a pod.
- Tracking when someone uses commands like kubectl exec to get into a running container and run commands or scripts.
- Monitoring activities in debug containers where users might run various tools.

For a complete walkthrough of configuring audit logging, see the [Audit Logging Guide](doc/audit-logging-guide.md).

To start using this feature, you need to have the Security Profiles Operator installed in your Kubernetes cluster.
Once it's installed, you can enable the JSON log enricher with this command:

```sh
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true}}}'
```

The audit JSON log enricher uses eBPF as a supplemental data source. While processing auditd logs from
`/var/log/audit/audit.log`, the enricher attempts to fetch ephemeral data from `/proc/<pid>` directories. Due to a
race condition, these files might be deleted before they can be read. To ensure data completeness, the enricher falls
back to fetching the necessary information from eBPF whenever it's not found in `/proc/<pid>`.

#### Audit JSON Log Enricher Configuration

Here's how to set up and fine-tune your audit logs.

##### Audit Log Interval

Set how often audit logs are created using the auditLogIntervalSeconds option. For example to configure audit log interval to 30 seconds use the command:

```sh
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogIntervalSeconds":30}}}}'
```

##### Audit Log File Destination

By default, audit logs go to your standard output in JSON lines format. You can send them to a file instead.

1. Configure the Volume Mount
   First, tell the security profiles operator where to store the log file on the node. You'll update the `security-profiles-operator-profile` ConfigMap with two keys:
   - `json-enricher-log-volume-source.json`: Defines the type of volume (e.g., host path, empty directory) where logs will be stored. This must be a JSON string representing a `corev1.VolumeSource` object. Refer to this [link](https://github.com/kubernetes/kubernetes/blob/master/pkg/apis/core/types.go#L58) for more details.
   - `json-enricher-log-volume-mount-path`: Specifies the directory path where the log file will be generated.

   Here's an example to set up a host path volume at `/tmp/logs`:

   ```json
   {
     "data": {
       "json-enricher-log-volume-mount-path": "/tmp/logs",
       "json-enricher-log-volume-source.json": "{\"hostPath\": {\"path\": \"/tmp/logs\",\"type\": \"DirectoryOrCreate\"}}"
     }
   }
   ```

   One of the ways to update the config map is to save this JSON in a file(`patch-volume-source.json`) and update the config map:

   ```sh
   kubectl patch configmap security-profiles-operator-profile -n security-profiles-operator --patch-file patch-volume-source.json
   ```

2. Restart the Operator

   The security profiles operator won't automatically pick up ConfigMap changes. You need to restart its pods for the new volume mount to take effect.

   ```sh
   kubectl rollout restart deployment security-profiles-operator -n security-profiles-operator
   ```

3. Set the Audit Log File Path

   Tell the JSON log enricher the full path to your audit log file (including the filename).

   ```sh
   kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogPath":"/tmp/logs/audit1.log"}}}}'
   ```

###### Audit Log File Fine-Tuning (Rotation)

For audit logging to a file, you can manage their size and how long they're kept. These options are similar to [Kubernetes API server log settings](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).

- `auditLogMaxSize`: The maximum size (in megabytes) a log file can reach before it's rotated (a new file is started).
- `auditLogMaxBackups`: The maximum number of older, rotated log files to keep. Set to 0 for no limit.
- `auditLogMaxAge`: The maximum number of days to keep old log files.
  You configure these by patching the JSON log enricher options:

```sh
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true,"jsonEnricherOptions":{"auditLogPath":"/tmp/logs/audit1.log","auditLogMaxSize":500,"auditLogMaxBackups":2,"auditLogMaxAge":10}}}}'
```

###### Verbosity (Debugging Logs)

Increase the logging level for the JSON log enricher container to help with debugging.

- 0: Minimal logs.
- 1: More detailed logs.

```sh
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableJsonEnricher":true}, "verbosity": 1}}'
```

#### How to Monitor Audit Logs for a Specific Pod

To enable audit logging for a single pod, follow these steps:

1. **Create a Seccomp profile:**

   Create a file (e.g., profile1.yaml) with the following content:

   ```shell
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
         - clone
         - getpid
   ```

   - This profile allows all normal actions (defaultAction: SCMP_ACT_ALLOW).
   - It specifically tells the system to log when a process tries to run a new program
     (execve), create a new process (clone), or get its own process ID (getpid).
     These actions often indicate user interaction within a pod.

2. **Apply the Seccomp Profile:**

   Use the kubectl apply command to create this profile in your cluster:

   ```shell
   kubectl apply -f profile1.yaml
   ```

3. **Create a Pod Using the Profile:**

   ```shell
   apiVersion: v1
   kind: Pod
   metadata:
     name: my-pod
     labels:
       app: my-app
   spec:
     securityContext:
       seccompProfile:
         type: Localhost
         localhostProfile: operator/profile1.json
     containers:
       - name: nginx
         image: quay.io/security-profiles-operator/test-nginx:1.19.1
   ```

   - type: `Localhost` means you're using a profile you've defined in the cluster.
   - localhostProfile: `operator/profile1.json` tells the pod to use the `profile1` you created. The operator/ part
     indicates where the Security Profiles Operator stores these profiles.

4. **Apply the Pod Definition:**

   Create the pod using kubectl apply:

   ```shell
   kubectl apply -f my-pod.yaml
   ```

5. **Monitor the Audit Logs:**

   There are two ways to monitor audit logs generated by the json-enricher container:

   a. To monitor the audit log tail:

   ```shell
   kubectl -n security-profiles-operator logs --since=1m --selector name=spod -c json-enricher --max-log-requests 6 -f
   ```

   b. To monitor the audit log file:

   The audit log file specified in the auditLogPath is written to the node's file system where the pod is running. To monitor or inspect the audit logs, you must access the node directly and check the file at the specified path (e.g., `/tmp/logs/audit1.log`).

   To monitor or inspect the audit logs, you need to:
   1. Identify the node on which the pod is scheduled:

   ```shell
   kubectl get pod my-pod -o wide
   ```

   2. SSH to a node and view the audit log:

   ```shell
   sudo ssh core@<node-name>
   cat /tmp/logs/audit1.log
   ```

   By following above steps, you can enable and monitor audit logs in JSON lines format for your Kubernetes pods,
   giving you better visibility into their activities.

#### Correlating with API Server Audit Log

By default, when you use `kubectl exec` to access a pod or container, Kubernetes doesn't pass the user's authentication
details into that session's environment. This means JSON Log Enricher can't include "who did what" information
for exec commands. The `uid`, `gid` recorded will map to the system user which in most cases would be the root user.

To address this, the JSON Log Enricher relies on mutating webhooks (`execmetadata.spo.io` and
`nodedebuggingpod.spo.io`). This webhook injects the exec request UID as an environment variable into the exec session.
Now, when the administrator enables audit logging on the API server, the webhooks will add an audit annotation,
`SPO_EXEC_REQUEST_UID`. The API server audit log will contain this information. This request ID will also be available
in the JSON lines produced by the JSON Log Enricher, specifically within the `requestUID` field.

By default, these webhooks are enabled for all the namespaces where JSON Log Enricher is enabled.
To reduce the scope of this webhook you can disable it for certain namespaces.

Edit the spod configuration:

```shell
kubectl edit spod spod -n security-profiles-operator
```

Add `webhook.options` to the spec:

Locate the `spec:` section and add the following webhook options block. This will tell the webhook to apply to
specific namespaces:

```yaml
# ... (rest of your spod configuration)
spec:
  webhook:
    options:
      - name: execmetadata.spo.io # or nodedebuggingpod.spo.io
        namespaceSelector:
        #...add rules
# ...
```

After saving your changes, the operator will reconfigure the mutating webhook, allowing request
details to be passed into `kubectl exec` sessions cluster-wide.

NOTE: This webhook injects the environment variable `SPO_EXEC_REQUEST_UID` into your exec request. If a container in your Pod
already defines an environment variable with this exact name, the webhook's injected value will override it for this
exec session.

When you use `kubectl debug node/<node-name>`, the `nodedebuggingpod.spo.io` webhook automatically injects the
`SPO_EXEC_REQUEST_UID` environment variable into the debug pod.

This webhook primarily identifies kubectl debug pods by the label `app.kubernetes.io/managed-by: "kubectl-debug"`,
which is added by the kubectl client.

Because this label might vary across different Kubernetes client implementations
(e.g., oc debug in OpenShift uses `debug.openshift.io/managed-by: "oc-debug"`),
you may need to configure additional `webhook.options` entries to ensure the webhook catches all relevant debug pods.

For example, to include `oc debug pods`:

```yaml
# ... (rest of your spod configuration)
spec:
  webhook:
    options:
      - name: nodedebuggingpod.spo.io
        objectSelector:
          matchLabels: # Use matchLabels for exact matching
            debug.openshift.io/managed-by: "oc-debug"
# ... other webhook rule details like rules, clientConfig, etc.
```

Reference: For more details on the label, see: https://github.com/kubernetes/kubernetes/pull/131791

### AppArmor Profile

Ensure that the spod daemon has AppArmor enabled:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

#### Record AppArmor profile

The operator is able to record AppArmor profiles for a workload only using the built-in eBPF recorder.

To use the eBPF recorder, enable it by patching the `spod` configuration:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableBpfRecorder":true}}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

Alternatively, make sure the operator deployment sets the `ENABLE_BPF_RECORDER`
environment variable to `true`. This method can be easier to set up during
installation than patching the `spod`.

We can verify that the recorder is up and running after the spod rollout has
been finished:

```
> kubectl -n security-profiles-operator logs --selector name=spod -c bpf-recorder
Found 6 pods, using pod/spod-h7dpm
I1115 12:02:45.991786  110307 main.go:182]  "msg"="Set logging verbosity to 0"
I1115 12:02:45.991901  110307 deleg.go:130] setup "msg"="starting component: bpf-recorder"  "buildDate"="1980-01-01T00:00:00Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.16.9" "libseccomp"="2.5.1" "platform"="linux/amd64" "version"="0.4.0-dev"
I1115 12:02:45.991955  110307 bpfrecorder.go:105] bpf-recorder "msg"="Setting up caches with expiry of 1h0m0s"
I1115 12:02:45.991973  110307 bpfrecorder.go:121] bpf-recorder "msg"="Starting log-enricher on node: ip-10-0-228-234.us-east-2.compute.internal"
I1115 12:02:45.994232  110307 bpfrecorder.go:152] bpf-recorder "msg"="Connecting to metrics server"
I1115 12:02:48.373469  110307 bpfrecorder.go:168] bpf-recorder "msg"="Got system mount namespace: 4026531840"
I1115 12:02:48.373518  110307 bpfrecorder.go:170] bpf-recorder "msg"="Doing BPF load/unload self-test"
I1115 12:02:48.373529  110307 bpfrecorder.go:336] bpf-recorder "msg"="Loading bpf module"
I1115 12:02:48.373570  110307 bpfrecorder.go:403] bpf-recorder "msg"="Using system btf file"
I1115 12:02:48.373770  110307 bpfrecorder.go:356] bpf-recorder "msg"="Loading bpf object from module"
I1115 12:02:48.403766  110307 bpfrecorder.go:362] bpf-recorder "msg"="Getting bpf program sys_enter"
I1115 12:02:48.403792  110307 bpfrecorder.go:368] bpf-recorder "msg"="Attaching bpf tracepoint"
I1115 12:02:48.406205  110307 bpfrecorder.go:373] bpf-recorder "msg"="Getting syscalls map"
I1115 12:02:48.406287  110307 bpfrecorder.go:379] bpf-recorder "msg"="Getting comms map"
I1115 12:02:48.406862  110307 bpfrecorder.go:396] bpf-recorder "msg"="Module successfully loaded, watching for events"
I1115 12:02:48.406908  110307 bpfrecorder.go:677] bpf-recorder "msg"="Unloading bpf module"
I1115 12:02:48.411636  110307 bpfrecorder.go:176] bpf-recorder "msg"="Starting GRPC API server"
```

You can now set up an AppArmor profile recording for `nginx` container by creating the following configuration:

```
kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: nginx-recording
  namespace: security-profiles-operator
spec:
  kind: AppArmorProfile
  recorder: Bpf
  podSelector:
    matchLabels:
      app: nginx
EOF

```

Now, an nginx container can be started. The operator will record an AppArmor profile for it in the background.

```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: security-profiles-operator
  labels:
    app: nginx
spec:
  containers:
    - name: nginx-container
      image: nginx
EOF
```

We can now let the container run for at least a few minutes to make sure that the required system resources are collected.

Stop the nginx pod, this will make the operator save and install the AppArmor profile in the cluster.

```
kubectl delete pod -n security-profiles-operator nginx-pod
```

We can check now that the profile was properly installed:

```
kubectl get apparmorprofile

# Output should show the AppArmor profile.

NAME                              AGE
nginx-recording-nginx-container   42h

# The content of the profile can be inspected.

kubectl get apparmorprofile -o yaml
```

_Known limitations:_

- The reconciler will simply load the profiles across the cluster. If an
  existing profile with the same name exists, it will be replaced. This might cause
  an existing profile to be overwritten (See [issue 2582](https://github.com/kubernetes-sigs/security-profiles-operator/issues/2582) for details).
- Restrictive profiles may block sub processes to be created, or a container from
  successfully loading. To work around the issue, set the AppArmor profile to
  complain mode by setting `.spec.mode` to `Complain`.

#### Use AppArmor profile

The recorded AppArmor profile can be used now to harden an nginx container. The profile should be referenced in the security context as follows:

```
# Create a dedicated namespace where the hardened container will be deployed.

kubectl create ns test-spo

# Deploy an nginx container with the custom AppArmor profile.

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: test-spo
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

# Check if the container is running properly.

kubectl get pod -n test-spo

# Output should show that the container is successfully running with AppArmor profile.

NAME        READY   STATUS    RESTARTS   AGE
nginx-pod   1/1     Running   0          8s
```

Note that in case of AppArmor, unlike seccomp, only the name of the profile is required in the security context of the container and not the path. You can see more details in the [official documentation](https://kubernetes.io/docs/tutorials/security/apparmor/).

### SELinux profile

Ensure that the running daemon has SELinux enabled:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"selinux":{"enable":true}}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

There are two kinds that can be used to define a SELinux profile - `SelinuxProfile` and `RawSelinuxProfile`.

The default one and the one created during workload recording is `SelinuxProfile`. It is more readable
and has several features that allow for better security hardening and better readability. The `RawSelinuxProfile`
kind should be used mostly when there's an already existing SELinux policy (perhaps created with udica)
that you wish to use in your cluster.

In particular, the `SelinuxProfile` kind:

- restricts the profiles to inherit from to the current namespace or a system-wide profile. Because there
  are typically many profiles installed on the system, but only a subset should be used by cluster workloads,
  the inheritable system profiles are listed in the `spod` instance in `spec.selinuxOptions.allowedSystemProfiles`.
  Depending on what distribution your nodes run, the base profile might vary, on RHEL-based systems, you might
  want to look at what profiles are shipped in the `container-selinux` RPM package.
- performs basic validation of the permissions, classes and labels
- adds a new keyword `@self` that describes the process using the policy. This allows to reuse a policy between
  workloads and namespaces easily, as the "usage" of the policy (see below) is based on the name and namespace.

Below is an example of a policy that can be used with a non-privileged nginx workload:

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

After the policy is created, we can wait for selinuxd to install it:

```bash
$ kubectl wait --for=condition=ready selinuxprofile nginx-secure
selinuxprofile.security-profiles-operator.x-k8s.io/nginx-secure condition met
```

The CIL-formatted policies are placed into an `emptyDir` owned by the SPO where you can view
the resulting CIL policy:

```shell
$ kubectl exec -it -c selinuxd spod-fm55x -- sh
sh-4.4# cat /etc/selinux.d/nginx-secure.cil
(block nginx-secure
(blockinherit container)
(allow process nginx-secure.process ( tcp_socket ( listen )))
(allow process http_cache_port_t ( tcp_socket ( name_bind )))
(allow process node_t ( tcp_socket ( node_bind )))
)
```

However, the binary policies are installed into the system policy store on the nodes, so you can verify
that a policy has been installed:

```shell
# semodule -l | grep nginx-secure
```

_Make a SELinux profile permissive:_
Similarly to how a `SeccompProfile` might have a default action `SCMP_ACT_LOG`
which would merely log violations of the policy, but not actually block the
container from executing, a `SelinuxProfile` can be marked as permissive
by setting `.spec.mode` to `Permissive`. This mode might be useful e.g. when
the policy is known or suspected to be incomplete and you'd prefer to just
watch for subsequent AVC denials after deploying the policy.

#### Record SELinux profile

The SELinux profiles can be recorded using the log enricher. You should make sure that it is enabled:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher":true}}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

Alternatively, make sure the operator deployment sets the `ENABLE_LOG_ENRICHER` variable,
to `true`, either by setting the environment variable in the deployment or by enabling
the variable through a `Subscription` resource, when installing the operator using OLM.
See [Constrain spod scheduling](installation.md#constrain-spod-scheduling) for an example of
setting `tolerations` and `affinity` on the SPOD.

Now the operator will take care of re-deploying the `spod` DaemonSet and the
enricher should be listening for new changes to the audit logs:

```
> kubectl -n security-profiles-operator logs -f ds/spod log-enricher
I0623 12:51:04.257814 1854764 deleg.go:130] setup "msg"="starting component: log-enricher"  "buildDate"="1980-01-01T00:00:00Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.16.2" "platform"="linux/amd64" "version"="0.4.0-dev"
I0623 12:51:04.257890 1854764 enricher.go:44] log-enricher "msg"="Starting log-enricher on node: 127.0.0.1"
I0623 12:51:04.257898 1854764 enricher.go:46] log-enricher "msg"="Connecting to local GRPC server"
I0623 12:51:04.258061 1854764 enricher.go:69] log-enricher "msg"="Reading from file /var/log/audit/audit.log"
2021/06/23 12:51:04 Sought /var/log/audit/audit.log - &{Offset:0 Whence:2}
```

To record by using the log enricher, create a `ProfileRecording` which is using
`recorder: Logs`:

You can now record a SELinux profile for `nginx` container by creating the following `ProfileRecording` configuration:

```
kubectl apply -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  name: nginx-recording
  namespace: security-profiles-operator
spec:
  kind: SelinuxProfile
  recorder: Logs
  podSelector:
    matchLabels:
      app: nginx
EOF
```

Now, an nginx container can be started with the SELinux type `selinuxrecording.process` in the security context.
The operator will record a SELinux profile for it in the background.

```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod
  namespace: security-profiles-operator
  labels:
    app: nginx
spec:
  containers:
    - name: nginx-container
      image: nginx
      securityContext:
        seLinuxOptions:
          type: selinuxrecording.process
EOF
```

We can now let the container run for at least a few minutes to make sure that the required system resources are collected.

Stop the nginx pod, this will make the operator save and install the SELinux profile in the cluster.

```
kubectl delete pod -n security-profiles-operator nginx-pod
```

We can check now that the profile was properly installed:

```
kubectl get selinuxprofile

# Output should show the selinux profile.

NAME                              USAGE                                     STATE
nginx-recording-nginx-container   nginx-recording-nginx-container.process   partial

# The content of the profile can be inspected.

kubectl get selinuxprofile -o yaml
```

#### Use SELinux profile

SELinux profiles are referenced based on their `USAGE` type name, which is `<ProfileName>_.process`.

Use this SELinux type in the workload manifest in the `.spec.containers[].securityContext.seLinuxOptions` attribute:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-secure
  namespace: security-profiles-operator
spec:
  containers:
    - image: nginxinc/nginx-unprivileged:1.21
      name: nginx
      securityContext:
        seLinuxOptions:
          # NOTE: This uses an appropriate SELinux type
          type: nginx-recording-nginx-container.process
```

The pod should properly start and run.

### Filtering Logs

The Security Profiles Operator Daemon (SPOD) supports advanced filtering of emitted logs through its enrichers,
allowing users to focus on relevant events.
Log filtering is managed by an array of filter rules configured directly on the SPOD resource. Two distinct fields are
available, each controlling a different enricher:

- `jsonEnricherFilters`: Applies filtering to the Audit JSON Log Enricher.
- `logEnricherFilters`: Applies filtering to the Log Enricher.

Example: Enabling Log Enricher and providing an empty filter array (no custom filtering)

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enricher":{"enableLogEnricher":true,"logEnricherFilters":[]}}}'
```

Each object within the `jsonEnricherFilters` or `logEnricherFilters` array conforms to the following structure:

| Field       | Type          | Description                                                                                                                                                                                                                                                                                                                 | Example Value                 |
| ----------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| priority    | integer       | Required. Defines the order of rule application. Rules with lower priority numbers are evaluated first (higher priority).                                                                                                                                                                                                   | 10, 100                       |
| level       | string        | Required. Determines the action to take if this rule matches a log line: <br/>- "Metadata": The log line is emitted (logged). <br/>- "None": The log line is dropped (not logged).                                                                                                                                          | "Metadata", "None"            |
| matchKeys   | array<string> | Required. An array of log statement keys (field names) that must all be present in the incoming log line for this rule to potentially match.                                                                                                                                                                                | ["namespace"], ["requestUID"] |
| matchValues | array<string> | Optional. An array of values. If provided, the values associated with any of the matchKeys (that were found in the log line) must match at least one of these matchValues. <br/>If matchValues is an empty array ([]) or omitted, the mere presence of all matchKeys is sufficient for a match, regardless of their values. | ["default"], ["test"]         |

#### Rule Evaluation Logic

When the enrichers start, all configured filter rules are parsed and loaded. For each incoming log statement:

- Rules are evaluated strictly in ascending order of their priority (lower numbers are evaluated first).
- The first rule that a log statement matches determines its fate. No subsequent rules will be evaluated for that particular log line.
- A log statement is considered a match for a rule if:
  - Any keys specified in matchKeys are present in the log statement.
  - AND (if matchValues is provided and not empty): At least one of the values associated with the matched matchKeys in the log statement matches at least one string in the rule's matchValues.
  - Also note that int values although provided as string will be converted to int
- Action Based on level:
  - If the matching rule's level is "Metadata", the log line is emitted.
  - If the matching rule's level is "None", the log line is dropped.
- Default Behavior: If no rule in the filter array matches the log statement, a default behavior of "Metadata" (log the line) will be applied.

#### Examples

1. Filtering JSON Audit Logs for Specific User Activity:

This example demonstrates logging only audit events associated with a requestUID, while filtering everything else. This is helpful for a JSON Audit log enricher to investigate the user activity like exec into a pod or end-user running some script inside a container.

The following JSON filter configuration can be used with the command below:

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

```
kubectl -n security-profiles-operator patch spod spod --type=merge -p {"spec":{"enricher":{"enableJsonEnricher": true, "jsonEnricherFilters": "[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"requestUID\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"version\"],\"matchValues\":[\"spo/v1_alpha\"]}]"}}}
```

2. Filtering Logs for a Specific Kubernetes Namespace:

This example logs log-enricher entries only from the default namespace and drops any other log lines for seccomp profile.

```
kubectl -n security-profiles-operator patch spod spod --type=merge -p {"spec":{"enricher":{"enableLogEnricher": true, "logEnricherFilters": "[{\"priority\":100,\"level\":\"Metadata\",\"matchKeys\":[\"namespace\"],\"matchValues\":[\"default\"]},{\"priority\":999, \"level\":\"None\",\"matchKeys\":[\"type\"],\"matchValues\":[\"seccomp\"]}]"}}}
```

### General Considerations

#### Base syscalls for a container runtime

An example of the minimum required syscalls for a runtime such as
[runc](https://github.com/opencontainers/runc) (tested on version 1.0.0) to
launch a container can be found in [the
examples](./examples/baseprofile-runc.yaml). You can use this example as a
starting point for creating custom profiles for your application. You can also
programmatically combine it with your custom profiles in order to build
application-specific profiles that only specify syscalls that are required on
top of the base calls needed for the container runtime. For example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: runc-v1.5.1
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - exit_group
```

If you're not using runc but the alternative
[crun](https://github.com/containers/crun), then you can do the same by using
the [corresponding example profile](./examples/baseprofile-crun.yaml) (tested
with version 1.29.1).

#### Recording profiles without applying them

In some cases, it might be desirable to record security profiles, but not install them.
Use-cases might include recording profiles in a CI system where the profiles would be
deployed in a subsequent verify run or recording profiles as part of a build process where the
profile would be deployed by the end-user.

To record profiles without installing them, set the `disableProfileAfterRecording`
attribute to `true` in the `ProfileRecording` CR. This option defaults to `false`, which
is the default behavior of the operator to install the profiles. When `disableProfileAfterRecording`
is set to `true`, the operator will not reconcile the profiles and will not install them. Partial
disabled profiles can still be merged and the resulting merged profile will be disabled.

On the profile level, this functionality is controlled by the `.spec.state` field. It is also
possible to create profile CRs in the `Disabled` state, although this functionality is probably
less interesting to end users and is mostly used for testing purposes. The `state` field defaults
to `Enabled`. Profiles that are disabled, either explicitly or by the `disableProfileAfterRecording`
flag, can be enabled by setting `.spec.state` to `Enabled` in the profile CR.

#### Disable profile recording

Profile recorder controller along with the corresponding sidecar container is disabled
when neither `enableBpfRecorder` nor `enableLogEnricher` is set in the SPOD configuration, and
automatically enabled when either one of them is on. The same applies when either
the BPF recorder of the log enricher are enabled using the environment variables
`ENABLE_BPF_RECORDER` or `ENABLE_LOG_ENRICHER` respectively.

Also, when running the daemon in standalone mode is possible to switch on the profile recorder
controller by providing the `with-recording` command line argument or setting the `ENABLE_RECORDING`
environment variable.

#### OCI Artifact support for base profiles

The operator supports pulling base profiles from container registries supporting
OCI artifacts, which are right now:

- [CNCF Distribution](https://github.com/distribution/distribution)
- [Azure Container Registry](https://aka.ms/acr)
- [Amazon Elastic Container Registry](https://aws.amazon.com/ecr)
- [Google Artifact Registry](https://cloud.google.com/artifact-registry)
- [GitHub Packages container registry](https://docs.github.com/en/packages/guides/about-github-container-registry)
- [Bundle Bar](https://bundle.bar/docs/supported-clients/oras)
- [Docker Hub](https://hub.docker.com)
- [Zot Registry](https://zotregistry.io)

To use that feature, just prefix the `baseProfileName` with `oci://`, like:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: SeccompProfile
metadata:
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: oci://ghcr.io/security-profiles/runc:v1.5.1
```

The resulting profile `profile1` will then contain all base syscalls from the
remote `runc` profile. It is also possible to reference the base profile by its
SHA256, like `oci://ghcr.io/security-profiles/runc@sha256:380…`. Please note
that all profiles must be signed using [sigstore (cosign)](https://github.com/sigstore/cosign)
signatures, otherwise the Security Profiles Operator will reject them. The OCI
artifact profiles also support different architectures, where the operator
always tries to select the correct one via `runtime.GOOS`/`runtime.GOARCH` but
also allows to fallback to a default profile.

The operator internally caches pulled artifacts up to 24 hours for 1000
profiles, means that they will be refreshed after that time period, if the stack
is full or the operator daemon gets restarted. It is also possible to define
additional `baseProfileName` for existing base profiles, so the operator will
recursively resolve them up to a level of 15 stacked profiles.

Because the resulting syscalls may be hidden from the user, we additionally annotate
the seccomp profile with the final results:

```console
> kubectl describe seccompprofile profile1
Name:         profile1
Labels:       spo.x-k8s.io/profile-id=SeccompProfile-profile1
Annotations:  syscalls:
                [{"names":["arch_prctl","brk","capget","capset","chdir","clone","close","dup3","epoll_create1","epoll_ctl","epoll_pwait","execve","exit_gr...
API Version:  security-profiles-operator.x-k8s.io/v1
```

We provide all available base profiles as part of the ["Security Profiles"
GitHub organization](https://github.com/orgs/security-profiles/packages).

#### Bind workloads to profiles with ProfileBindings

If you do not want to directly modify the SecurityContext of a Pod, for instance
if you are deploying a public application, you can use the ProfileBinding
resource to bind a security profile to a container's securityContext.

You need to enable the profile binding for a namespace by applying the label
`spo.x-k8s.io/enable-binding` as following:

```sh
$ kubectl label ns spo-test spo.x-k8s.io/enable-binding=
```

To bind a Pod that uses an 'nginx:1.19.1' image to the 'profile-complain'
example seccomp profile, create a ProfileBinding in the same namespace as both
the Pod and the SeccompProfile:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: nginx-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain
  image: nginx:1.19.1
```

You can enable a default profile binding by using the string "\*" as the image name.
This will only apply a profile binding if no other profile binding matches a container in the pod.

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileBinding
metadata:
  name: nginx-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain
  image: *
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
  name: nginx-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain
  image: nginx:1.19.1
  podSelector:
    matchLabels:
      app: nginx
```

If the Pod is already running, it will need to be restarted in order to pick up
the profile binding. Once the binding is created and the Pod is created or
recreated, the SeccompProfile should be applied to the container whose image
name matches the binding:

```sh
$ kubectl get pod test-pod -o jsonpath='{.spec.containers[*].securityContext.seccompProfile}'
{"localhostProfile":"operator/profile-complain-unsafe.json","type":"Localhost"}
```

Binding a SELinux profile works in the same way, except you'd use the `SelinuxProfile` kind.
`RawSelinuxProfiles` are currently not supported.

#### Merging per-container profile instances

By default, each container instance will be recorded into a separate
profile. This is mostly visible when recording pods managed by a replicating
controller (Deployment, DaemonSet, etc.). A realistic example might
be a workload being recorded in a test environment where the recorded
Deployment consists of several replicas, only one of which is receiving
the test traffic. After the recording is complete, only the container that
was receiving the traffic would have contained all the syscalls that were
actually used.

In this case, it might be useful to merge the per-container profiles
into a single profile. This can be done by setting the `mergeStrategy`
attribute to `containers` in the `ProfileRecording`. Note that the following
example uses a `SeccompProfile` as the `kind` but the same applies to
`SelinuxProfile` as well.

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1
kind: ProfileRecording
metadata:
  # The name of the Recording is the same as the resulting `SeccompProfile` CRD
  # after reconciliation.
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
      serviceAccountName: spo-record-sa
      containers:
        - name: nginx-record
          image: quay.io/security-profiles-operator/test-nginx-unprivileged:1.21
          ports:
            - containerPort: 8080
```

You'll see that the deployment spawns three replicas. To test the merging feature, you
can perform an action in one of the pods, for example:

```bash
> kubectl exec nginx-deploy-65bcbb956f-gmbrj -- bash -c "mknod /tmp/foo p"
```

Note that this is a silly example, but shows the feature in action.

To record the individual profiles, delete the deployment:

```bash
> kubectl delete deployment nginx-deploy
```

The profiles will be reconciled, one per container. Note that the profiles are marked as
"partial" and the spod daemon instances do not reconcile the profiles.

```bash
> kubectl get sp -lspo.x-k8s.io/recording-id=test-recording --show-labels
NAME                                STATUS    AGE     LABELS
test-recording-nginx-record-gmbrj   Partial   2m50s   spo.x-k8s.io/container-id=sp-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-sp-record-gmbrj,spo.x-k8s.io/recording-id=test-recording
test-recording-nginx-record-lclnb   Partial   2m50s   spo.x-k8s.io/container-id=sp-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-sp-record-lclnb,spo.x-k8s.io/recording-id=test-recording
test-recording-nginx-record-wdv2r   Partial   2m50s   spo.x-k8s.io/container-id=sp-record,spo.x-k8s.io/partial=true,spo.x-k8s.io/profile-id=SeccompProfile-test-recording-sp-record-wdv2r,spo.x-k8s.io/recording-id=test-recording
```

Inspecting the first partial profile, which corresponds to the pod where we ran the extra command
shows that mknod is allowed:

```bash
> kubectl get sp test-recording-nginx-record-gmbrj -o yaml | grep mknod
  - mknod
```

On the other hand the others do not:

```bash
> kubectl get sp test-recording-nginx-record-lclnb -o yaml | grep mknod
> kubectl get sp test-recording-nginx-record-wdv2r -o yaml | grep mknod
```

To merge the profiles, delete the profile recording to indicate that
you are finished with recording the workload. This would trigger the
merge operation done by the controller and the resulting profile will be
reconciled by the controller as seen from the `Installed` state:

```bash
> kubectl delete profilerecording test-recording
profilerecording.security-profiles-operator.x-k8s.io "test-recording" deleted
> kubectl get sp -lspo.x-k8s.io/recording-id=test-recording
NAME                          STATUS      AGE
test-recording-nginx-record   Installed   17m
```

The resulting profile will contain all the syscalls that were used by any of the containers,
including the `mknod` syscall:

```bash
> kubectl get sp test-recording-nginx-record -o yaml | grep mknod
  - mknod
```

**Syscall coverage annotation**

When a `SeccompProfile` is produced by a merge (`mergeStrategy: Containers`), the resulting profile
carries an informational annotation, `spo.x-k8s.io/syscall-coverage`, that records how the merged
allowlist was assembled from the individual partial profiles. Its value is a small JSON document:

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

The semantics are literal, per syscall: `total` is **M**, the number of partial profiles that were
collected and included in the merge, and each entry under `syscalls` is **N**, the number of those
partial profiles that contained that syscall. A syscall that appears more than once inside a single
partial profile still counts once for that profile. In the example above, `read` and `write` were
observed in all three recorded containers, while `mknod` was observed in only one.

This is **observation coverage, not confidence or probability**, and it does not measure how many
times a syscall was invoked. `total` counts the partial profiles that were actually collected, which
is not necessarily the number of executions that occurred (for example, a recording can be lost if
the operator restarts mid-recording). Recorded replicas usually run identical images and are
therefore correlated rather than independent samples, so the counts should not be read as a
statistical measure.

The annotation is purely informational: it never changes the generated seccomp allowlist, and the
enforced profile is exactly what the merge produces regardless of these counts. Treat it as a review
aid only. **Do not remove syscalls from a generated profile based solely on a low coverage count**,
since a syscall observed in only one replica may still be required on a code path the other replicas
did not exercise.

