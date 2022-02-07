# Installation and Usage

<!-- toc -->

- [Features](#features)
- [Tutorials and Demos](#tutorials-and-demos)
- [Install operator](#install-operator)
- [Set logging verbosity](#set-logging-verbosity)
- [Create Profile](#create-profile)
  - [Apply profile to pod](#apply-profile-to-pod)
  - [Base syscalls for a container runtime](#base-syscalls-for-a-container-runtime)
  - [Bind workloads to profiles with ProfileBindings](#bind-workloads-to-profiles-with-profilebindings)
  - [Record profiles from workloads with <code>ProfileRecordings</code>](#record-profiles-from-workloads-with-profilerecordings)
    - [Hook based recording](#hook-based-recording)
    - [Log enricher based recording](#log-enricher-based-recording)
    - [eBPF based recording](#ebpf-based-recording)
- [Restricting to a Single Namespace](#restricting-to-a-single-namespace)
- [Using metrics](#using-metrics)
  - [Available metrics](#available-metrics)
  - [Automatic ServiceMonitor deployment](#automatic-servicemonitor-deployment)
- [Using the log enricher](#using-the-log-enricher)
- [Troubleshooting](#troubleshooting)
  - [Enable CPU and memory profiling](#enable-cpu-and-memory-profiling)
  - [Use a custom <code>/proc</code> location for nested environments like <code>kind</code>](#use-a-custom-proc-location-for-nested-environments-like-kind)
- [Uninstalling](#uninstalling)
<!-- /toc -->

## Features

The feature scope of the security-profiles-operator is right now limited to:

- Adds a `SeccompProfile` CRD (alpha) to store seccomp profiles.
- Adds a `ProfileBinding` CRD (alpha) to bind security profiles to pods.
- Adds a `ProfileRecording` CRD (alpha) to record security profiles from workloads.
- Synchronize seccomp profiles across all worker nodes.
- Validates if a node supports seccomp and do not synchronize if not.
- Providing metrics endpoints

## Tutorials and Demos

- [Introduction to Seccomp and the Kubernetes Seccomp Operator](https://youtu.be/exg_zrg16SI)
  ([@saschagrunert](https://github.com/saschagrunert) and [@hasheddan](https://github.com/hasheddan))
- [Enhancing Kubernetes with the Security Profiles Operator](https://youtu.be/xisAIB3kOJo)
  ([@cmurphy](https://github.com/cmurphy) and [@saschagrunert](https://github.com/saschagrunert))

## Install operator

The operator container image consists of an image manifest which supports the
architectures `amd64` and `arm64` for now. To deploy the operator, first install
cert-manager via `kubectl`:

```sh
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.1/cert-manager.yaml
$ kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager
```

Then apply the operator manifest:

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml
```

## Set logging verbosity

The operator supports the default logging verbosity of `0` and an enhanced `1`.
To switch to the enhanced logging verbosity, patch the spod config by adjusting
the value:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"verbosity":1}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

The daemon should now indicate that it's using the new logging verbosity:

```
> k logs ds/spod security-profiles-operator | head -n1
I1111 15:13:16.942837       1 main.go:182]  "msg"="Set logging verbosity to 1"
```

## Create Profile

Use the `SeccompProfile` kind to create profiles. Example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
```

This seccomp profile will be saved at the path:

`/var/lib/kubelet/seccomp/operator/my-namespace/profile1.json`.

An init container will set up the root directory of the operator to be able to
run it without root G/UID. This will be done by creating a symlink from the
rootless profile storage `/var/lib/security-profiles-operator` to the default seccomp root
path inside of the kubelet root `/var/lib/kubelet/seccomp/operator`.

### Apply profile to pod

Create a pod using one of the created profiles. On Kubernetes >= 1.19, the
profile can be specified as part of the pod's security context:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/my-namespace/profile1.json
  containers:
    - name: test-container
      image: nginx
```

Prior to Kubernetes 1.19, the seccomp profile is controlled by an annotation:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/my-namespace/profile1.json"
spec:
  containers:
    - name: test-container
      image: nginx
```

You can find the profile path of the seccomp profile by checking the
`seccompProfile.localhostProfile` attribute:

```sh
$ kubectl --namespace my-namespace get seccompprofile profile1 --output wide
NAME       STATUS   AGE   SECCOMPPROFILE.LOCALHOSTPROFILE
profile1   Active   14s   operator/my-namespace/profile1.json
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
    "localhostProfile": "operator/my-namespace/profile1.json",
    "type": "Localhost"
  }
}
```

### Base syscalls for a container runtime

An example of the minimum required syscalls for a runtime such as
[runc](https://github.com/opencontainers/runc) (tested on version 1.0.0) to
launch a container can be found in [the
examples](./examples/baseprofile-runc.yaml). You can use this example as a
starting point for creating custom profiles for your application. You can also
programmatically combine it with your custom profiles in order to build
application-specific profiles that only specify syscalls that are required on
top of the base calls needed for the container runtime. For example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: runc-v1.0.0
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - exit_group
```

If you're not using runc but the alternative
[crun](https://github.com/containers/crun), then you can do the same by using
the [corresponding example profile](./examples/baseprofile-crun.yaml) (tested
with version 0.20.1).

### Bind workloads to profiles with ProfileBindings

If you do not want to directly modify the SecurityContext of a Pod, for instance
if you are deploying a public application, you can use the ProfileBinding
resource to bind a security profile to a container's securityContext. Currently,
the ProfileBinding resource can only refer to a SeccompProfile.

To bind a Pod that uses an 'nginx:1.19.1' image to the 'profile-complain'
example seccomp profile, create a ProfileBinding in the same namespace as both
the Pod and the SeccompProfile:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileBinding
metadata:
  name: nginx-binding
spec:
  profileRef:
    kind: SeccompProfile
    name: profile-complain
  image: nginx:1.19.1
```

If the Pod is already running, it will need to be restarted in order to pick up
the profile binding. Once the binding is created and the Pod is created or
recreated, the SeccompProfile should be applied to the container whose image
name matches the binding:

```sh
$ kubectl get pod test-pod -o jsonpath='{.spec.containers[*].securityContext.seccompProfile}'
{"localhostProfile":"operator/default/generic/profile-complain-unsafe.json","type":"Localhost"}
```

### Record profiles from workloads with `ProfileRecordings`

The operator is capable of recording seccomp profiles by the usage of the
[oci-seccomp-bpf-hook][bpf-hook] or by evaluating the [audit][auditd] or
[syslog][syslog] files. Both methods have its pros and cons as well as separate
technical requirements.

#### Hook based recording

[OCI hooks][hooks] are part of the OCI runtime-spec, which allow to hook into
the container creation process. The Kubernetes container runtime [CRI-O][cri-o]
supports those hooks out of the box, but has to be configured to listen on the
hooks directory where the [oci-seccomp-bpf-hook.json][hook-json] is located.
This can be done via a drop-in configuration file, for example:

```
$ cat /etc/crio/crio.conf.d/03-hooks.conf
[crio.runtime]
hooks_dir = [
    "/path/to/seccomp/hook",
]
```

The hook references a [path][path] to the actual binary which gets executed on
`prestart`. Please note that at least CRI-O v1.21.0 is required to let the hook
and CRI-O work nicely together.

[bpf-hook]: https://github.com/containers/oci-seccomp-bpf-hook
[hooks]: https://github.com/opencontainers/runtime-spec/blob/fd895fb/config.md#posix-platform-hooks
[cri-o]: https://cri-o.io
[hook-json]: https://github.com/containers/oci-seccomp-bpf-hook/blob/50e711/oci-seccomp-bpf-hook.json
[path]: https://github.com/containers/oci-seccomp-bpf-hook/blob/50e711/oci-seccomp-bpf-hook.json#L4

Unfortunately, [containerd][containerd] is not [capable of running OCI
hooks][containerd-hooks], yet.

[containerd]: https://containerd.io
[containerd-hooks]: https://github.com/containerd/cri/issues/405

We can create a new `ProfileRecording` to indicate to the operator that a
specific workload should be recorded:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  recorder: hook
  podSelector:
    matchLabels:
      app: alpine
```

Please note the `recorder: hook`, which has to be used to use the hook based
recording feature. Recordings are linked to workloads by using a `podSelector`,
which means that every workload, which contains the label `app=alpine`, will
from now on be recorded into the `SeccompProfile` CRD with the name
`test-recording`. Please be aware that the resource will be overwritten if
recordings are executed multiple times.

Now we can start the recording by running a workload which contains the label:

```
$ kubectl run --rm -it my-pod --image=alpine --labels app=alpine -- sh
/ # mkdir test
```

If we exit the workload, then it automatically will be removed because of the
`--rm` CLI flag. Once the workload is removed, the operator will create the CRD
for us. The name of the CRD is suffixed with the pod name:

```
$ kubectl describe seccompprofile test-recording-my-pod
Name:         test-recording-my-pod
Namespace:    security-profiles-operator
…
Spec:
  Architectures:
    SCMP_ARCH_X86_64
  Default Action:  SCMP_ACT_ERRNO
  Syscalls:
    Action:  SCMP_ACT_ALLOW
    Names:
      …[other syscalls]…
      mkdir
      …[other syscalls]…
Status:
  Localhost Profile:  operator/security-profiles-operator/test-recording-my-pod.json
  Path:               /var/lib/kubelet/seccomp/operator/security-profiles-operator/test-recording-my-pod.json
  Status:             Active
Events:
  Type    Reason                 Age                From             Message
  ----    ------                 ----               ----             -------
  Normal  SeccompProfileCreated  32s                profilerecorder  seccomp profile created
  Normal  SavedSeccompProfile    30s (x3 over 32s)  profile          Successfully saved profile to disk
```

We can see that the created profile also contains the executed `mkdir` command
as well as got reconciled to every node.

The events of the operator will give more insights about the overall process or
if anything goes wrong:

```
> kubectl get events | grep -i record
3m45s       Normal    SeccompProfileRecording        pod/alpine                                                Recording seccomp profile
3m29s       Normal    SeccompProfileCreated          seccompprofile/test-recording                             seccomp profile created
11s         Normal    SavedSeccompProfile            seccompprofile/test-recording                             Successfully saved profile to disk
```

It is also possible to record profiles from multiple containers, for example by
using this recording and Pod manifest:

```
---
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: recording
spec:
  kind: SeccompProfile
  recorder: hook
  podSelector:
    matchLabels:
      app: my-app
---
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
  restartPolicy: Never
```

If the workload gets created and removed again, then the recorder will produce
two seccomp profiles for each container:

```
> kubectl get sp -o wide
NAME              STATUS   AGE   LOCALHOSTPROFILE
recording-nginx   Active   32s   operator/default/recording-nginx.json
recording-redis   Active   32s   operator/default/recording-redis.json
```

On top of that, we're able to record distinguishable replicas, for example when
working with Deployments like these:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  selector:
    matchLabels:
      app: my-app
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: nginx
        image: quay.io/security-profiles-operator/test-nginx:1.19.1
```

If the deployment gets deleted, then the operator writes three seccomp profiles
instead of just one:

```
> kubectl get sp -o wide
NAME                STATUS   AGE   LOCALHOSTPROFILE
recording-nginx-0   Active   51s   operator/default/recording-nginx-0.json
recording-nginx-1   Active   51s   operator/default/recording-nginx-1.json
recording-nginx-2   Active   55s   operator/default/recording-nginx-2.json
```

This may be helpful when testing in load balanced scenarios where the profiles
have to be compared in an additional step.

Please note that we encourage you to only use this recording approach for
development purposes. It is not recommended to use the OCI hook in production
clusters because it runs as highly privileged process to trace the container
workload via a BPF module.

#### Log enricher based recording

When using the log enricher for recording seccomp profiles, please ensure that
the feature [is enabled within the spod](#using-the-log-enricher) configuration
resource. The log based recording works in the same way with
[containerd][containerd] and [CRI-O][cri-o], while using the node local logs as
input source of truth.

To record by using the enricher, create a `ProfileRecording` which is using
`recorder: logs`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  recorder: logs
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
> kubectl -n security-profiles-operator logs --since=1m ds/spod log-enricher
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

#### eBPF based recording

The operator also supports an [eBPF](https://ebpf.io) based recorder. This
recorder only supports seccomp profiles for now. Recording via ebpf works for
kernels which expose the `/sys/kernel/btf/vmlinux` file per default as well as a
[custom list of selected Linux kernels](bpf-support.md).

To use the recorder, enable it by patching the `spod` configuration:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableBpfRecorder":true}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

We can verify that the recorder is up and running after the spod rollout has
been finished:

```
> kubectl logs ds/spod -c bpf-recorder
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
`ProfileRecording` which is using `recorder: bpf`:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: my-recording
spec:
  kind: SeccompProfile
  recorder: bpf
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
> kubectl -n security-profiles-operator logs --since=1m ds/spod log-enricher
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

## Restricting to a Single Namespace

The security-profiles-operator can optionally be run to watch SeccompProfiles in
a single namespace. This is advantageous because it allows for tightening the
RBAC permissions required by the operator's ServiceAccount. To modify the
operator deployment to run in a single namespace, use the
`namespace-operator.yaml` manifest with your namespace of choice:

```sh
NAMESPACE=<your-namespace>

curl https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/namespace-operator.yaml | sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
```

## Using metrics

The security-profiles-operator provides two metrics endpoints, which are secured
by a [kube-rbac-proxy](https://github.com/brancz/kube-rbac-proxy) sidecar
container. All metrics are exposd via the `metrics` service within the
`security-profiles-operator` namespace:

```
> kubectl get svc/metrics -n security-profiles-operator
NAME      TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
metrics   ClusterIP   10.0.0.228   <none>        443/TCP   43s
```

The operator ships a cluster role and corresponding binding `spo-metrics-client`
to retrieve the metrics from within the cluster. There are two metrics paths
available:

- `metrics.security-profiles-operator/metrics`: for controller runtime metrics
- `metrics.security-profiles-operator/metrics-spod`: for the operator daemon metrics

To retrieve the metrics, just query the service endpoint by using the default
serviceaccount token in the `security-profiles-operator` namespace:

```
> kubectl run --rm -i --restart=Never --image=registry.fedoraproject.org/fedora-minimal:latest \
    -n security-profiles-operator metrics-test -- bash -c \
    'curl -ks -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://metrics.security-profiles-operator/metrics-spod'
…
# HELP security_profiles_operator_seccomp_profile_total Counter about seccomp profile operations.
# TYPE security_profiles_operator_seccomp_profile_total counter
security_profiles_operator_seccomp_profile_total{operation="delete"} 1
security_profiles_operator_seccomp_profile_total{operation="update"} 2
…
```

If the metrics have to be retrieved from a different namespace, just link the
service account to the `spo-metrics-client` `ClusterRoleBinding` or create a new
one:

```
> kubectl get clusterrolebinding spo-metrics-client -o wide
NAME                 ROLE                             AGE   USERS   GROUPS   SERVICEACCOUNTS
spo-metrics-client   ClusterRole/spo-metrics-client   35m                    security-profiles-operator/default
```

Every metrics server pod from the DaemonSet runs with the same set of certificates
(secret `metrics-server-cert`: `tls.crt` and `tls.key`) in the
`security-profiles-operator` namespace. This means a pod like this can be used
to omit the `--insecure/-k` flag:

```yaml
---
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
    - name: test-container
      image: registry.fedoraproject.org/fedora-minimal:latest
      command:
        - bash
        - -c
        - |
          curl -s --cacert /var/run/secrets/metrics/ca.crt \
            -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
            https://metrics.security-profiles-operator/metrics-spod
      volumeMounts:
        - mountPath: /var/run/secrets/metrics
          name: metrics-cert-volume
          readOnly: true
  restartPolicy: Never
  volumes:
    - name: metrics-cert-volume
      secret:
        defaultMode: 420
        secretName: metrics-server-cert
```

### Available metrics

The controller-runtime (`/metrics`) as well as the DaemonSet endpoint
(`/metrics-spod`) already provide a set of default metrics. Beside that, those
additional metrics are provided by the daemon, which are always prefixed with
`security_profiles_operator_`:

| Metric Key                    | Possible Labels                                                                                                                                                                                            | Type    | Purpose                                                                              |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| `seccomp_profile_total`       | `operation={delete,update}`                                                                                                                                                                                | Counter | Amount of seccomp profile operations.                                                |
| `seccomp_profile_audit_total` | `node`, `namespace`, `pod`, `container`, `executable`, `syscall`                                                                                                                                           | Counter | Amount of seccomp profile audit operations. Requires the log-enricher to be enabled. |
| `seccomp_profile_bpf_total`   | `node`, `mount_namespace`, `profile`                                                                                                                                                                       | Counter | Amount of seccomp profile bpf operations. Requires the bpf-recorder to be enabled.   |
| `seccomp_profile_error_total` | `reason={`<br>`SeccompNotSupportedOnNode,`<br>`InvalidSeccompProfile,`<br>`CannotSaveSeccompProfile,`<br>`CannotRemoveSeccompProfile,`<br>`CannotUpdateSeccompProfile,`<br>`CannotUpdateNodeStatus`<br>`}` | Counter | Amount of seccomp profile errors.                                                    |
| `selinux_profile_total`       | `operation={delete,update}`                                                                                                                                                                                | Counter | Amount of selinux profile operations.                                                |
| `selinux_profile_audit_total` | `node`, `namespace`, `pod`, `container`, `executable`, `syscall`                                                                                                                                           | Counter | Amount of selinux profile audit operations. Requires the log-enricher to be enabled. |
| `selinux_profile_error_total` | `reason={`<br>`CannotSaveSelinuxPolicy,`<br>`CannotUpdatePolicyStatus,`<br>`CannotRemoveSelinuxPolicy,`<br>`CannotContactSelinuxd,`<br>`CannotWritePolicyFile,`<br>`CannotGetPolicyStatus`<br>`}`          | Counter | Amount of selinux profile errors.                                                    |

### Automatic ServiceMonitor deployment

If the Kubernetes cluster has the [Prometheus
Operator](https://github.com/prometheus-operator/prometheus-operator) deployed,
then the Security Profiles Operator will automatically create a `ServiceMonitor`
resource within its namespace. This monitor allows automatic metrics discovery
within the cluster, which is pointing to the right service, TLS certificates as
well as bearer token secret.

When running on OpenShift, then the only configuration to be done is enabling
user workloads by applying the following config map:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-monitoring-config
  namespace: openshift-monitoring
data:
  config.yaml: |
    enableUserWorkload: true
```

After that, the Security Profiles Operator can be deployed or updated, which
will reconcile the `ServiceMonitor` into the cluster:

```
> kubectl -n security-profiles-operator logs security-profiles-operator-d7c8cfc86-47qh2 | grep monitor
I0520 09:29:35.578165       1 spod_controller.go:282] spod-config "msg"="Deploying operator service monitor"
```

```
> kubectl -n security-profiles-operator get servicemonitor
NAME                                 AGE
security-profiles-operator-monitor   35m
```

We can now verify in the Prometheus targets that all endpoints are serving the
metrics:

```
> kubectl port-forward -n openshift-user-workload-monitoring pod/prometheus-user-workload-0 9090
Forwarding from 127.0.0.1:9090 -> 9090
Forwarding from [::1]:9090 -> 9090
```

![prometheus targets](doc/img/prometheus-targets.png)

The OpenShift UI is now able to display the operator metrics, too:

![prometheus targets](doc/img/openshift-metrics.png)

## Using the log enricher

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
  in place which has direct influence on the log enrichment. To diable the rate
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
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableLogEnricher":true}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

Now the operator will take care of re-deploying the `spod` DaemonSet and the
enricher should listening on new changes to the audit logs:

```
> kubectl -n security-profiles-operator logs -f ds/spod log-enricher
I0623 12:51:04.257814 1854764 deleg.go:130] setup "msg"="starting component: log-enricher"  "buildDate"="1980-01-01T00:00:00Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.16.2" "platform"="linux/amd64" "version"="0.4.0-dev"
I0623 12:51:04.257890 1854764 enricher.go:44] log-enricher "msg"="Starting log-enricher on node: 127.0.0.1"
I0623 12:51:04.257898 1854764 enricher.go:46] log-enricher "msg"="Connecting to local GRPC server"
I0623 12:51:04.258061 1854764 enricher.go:69] log-enricher "msg"="Reading from file /var/log/audit/audit.log"
2021/06/23 12:51:04 Seeked /var/log/audit/audit.log - &{Offset:0 Whence:2}
```

To be able to trace an application, we have to create a logging profile like this:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log
  namespace: default
spec:
  defaultAction: SCMP_ACT_LOG
```

After the profile has been created, a corresponding workload can be started to
use the profile:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: log-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/default/log.json
  containers:
    - name: log-container
      image: nginx
```

If the pod is running, then we can examine the log enricher output:

```
> kubectl -n security-profiles-operator logs -f ds/spod log-enricher
…
I0623 12:59:10.220291 1854764 container.go:77] log-enricher "msg"="container ID is still empty, retrying"  "containerName"="log-container"
I0623 12:59:10.724938 1854764 container.go:77] log-enricher "msg"="container ID is still empty, retrying"  "containerName"="log-container"
I0623 12:59:11.479869 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=3 "syscallName"="close" "timestamp"="1624453150.205:1061" "type"="seccomp"
I0623 12:59:11.487323 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=157 "syscallName"="prctl" "timestamp"="1624453150.205:1062" "type"="seccomp"
I0623 12:59:11.492157 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=157 "syscallName"="prctl" "timestamp"="1624453150.205:1063" "type"="seccomp"
…
I0623 12:59:20.258523 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=12 "syscallName"="brk" "timestamp"="1624453150.235:2873" "type"="seccomp"
I0623 12:59:20.263349 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=21 "syscallName"="access" "timestamp"="1624453150.235:2874" "type"="seccomp"
I0623 12:59:20.354091 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=257 "syscallName"="openat" "timestamp"="1624453150.235:2875" "type"="seccomp"
I0623 12:59:20.358844 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=5 "syscallName"="fstat" "timestamp"="1624453150.235:2876" "type"="seccomp"
I0623 12:59:20.363510 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=9 "syscallName"="mmap" "timestamp"="1624453150.235:2877" "type"="seccomp"
I0623 12:59:20.454127 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=3 "syscallName"="close" "timestamp"="1624453150.235:2878" "type"="seccomp"
I0623 12:59:20.458654 1854764 enricher.go:111] log-enricher "msg"="audit"  "container"="log-container" "executable"="/usr/sbin/nginx" "namespace"="default" "node"="127.0.0.1" "pid"=1905792 "pod"="log-pod" "syscallID"=257 "syscallName"="openat" "timestamp"="1624453150.235:2879" "type"="seccomp"
…
```

The startup of the nginx container already invokes a huge amount of syscalls, which
are now all available within a human readable way within the log enricher.

The metrics endpoint of the Security Profiles Operator can be used to examine
the log enricher data in a more structured way. This means that each syscall
invocation will create a new metric entry
`security_profiles_operator_seccomp_profile_audit_total` containing the
corresponding metadata as labels:

```
# HELP security_profiles_operator_seccomp_profile_audit_total Counter about seccomp profile audits, requires the log enricher to be enabled.
# TYPE security_profiles_operator_seccomp_profile_audit_total counter
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="access"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="arch_prctl"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="bind"} 2
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="brk"} 18
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="close"} 154
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="pread64"} 4
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="prlimit64"} 3
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="pwrite64"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="recvmsg"} 120
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="rt_sigaction"} 14
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="rt_sigprocmask"} 14
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="rt_sigsuspend"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="sendmsg"} 68
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="set_robust_list"} 13
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="set_tid_address"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="setgid"} 12
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="setgroups"} 12
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="setsockopt"} 3
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="setuid"} 12
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="socket"} 6
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="socketpair"} 24
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="stat"} 6
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="sysinfo"} 1
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="uname"} 2
security_profiles_operator_seccomp_profile_audit_total{container="log-container",executable="/usr/sbin/nginx",namespace="default",node="127.0.0.1",pod="log-pod",syscall="write"} 20
```

## Troubleshooting

Confirm that the profile is being reconciled:

```sh
$ kubectl -n security-profiles-operator logs security-profiles-operator-mzw9t
I1019 19:34:14.942464       1 main.go:90] setup "msg"="starting security-profiles-operator"  "buildDate"="2020-10-19T19:31:24Z" "compiler"="gc" "gitCommit"="a3ef0e1ea6405092268c18f240b62015c247dd9d" "gitTreeState"="dirty" "goVersion"="go1.15.1" "platform"="linux/amd64" "version"="0.2.0-dev"
I1019 19:34:15.348389       1 listener.go:44] controller-runtime/metrics "msg"="metrics server is starting to listen"  "addr"=":8080"
I1019 19:34:15.349076       1 main.go:126] setup "msg"="starting manager"
I1019 19:34:15.349449       1 internal.go:391] controller-runtime/manager "msg"="starting metrics server"  "path"="/metrics"
I1019 19:34:15.350201       1 controller.go:142] controller "msg"="Starting EventSource" "controller"="profile" "reconcilerGroup"="security-profiles-operator.x-k8s.io" "reconcilerKind"="SeccompProfile" "source"={"Type":{"metadata":{"creationTimestamp":null},"spec":{"defaultAction":""}}}
I1019 19:34:15.450674       1 controller.go:149] controller "msg"="Starting Controller" "controller"="profile" "reconcilerGroup"="security-profiles-operator.x-k8s.io" "reconcilerKind"="SeccompProfile"
I1019 19:34:15.450757       1 controller.go:176] controller "msg"="Starting workers" "controller"="profile" "reconcilerGroup"="security-profiles-operator.x-k8s.io" "reconcilerKind"="SeccompProfile" "worker count"=1
I1019 19:34:15.453102       1 profile.go:148] profile "msg"="Reconciled profile from SeccompProfile" "namespace"="security-profiles-operator" "profile"="nginx-1.19.1" "name"="nginx-1.19.1" "resource version"="728"
I1019 19:34:15.453618       1 profile.go:148] profile "msg"="Reconciled profile from SeccompProfile" "namespace"="security-profiles-operator" "profile"="security-profiles-operator" "name"="security-profiles-operator" "resource version"="729"
```

Confirm that the seccomp profiles are saved into the correct path:

```sh
$ kubectl exec -t -n security-profiles-operator security-profiles-operator-v6p2h -- ls /var/lib/kubelet/seccomp/operator/my-namespace/my-workload
profile-block.json
profile-complain.json
```

Please note corrupted seccomp profiles can disrupt your workloads. Therefore, ensure that the user used cannot be abused by:

- Not creating that user on the actual node.
- Restricting the user ID to only security-profiles-operator (i.e. using PSP).
- Not allowing other workloads to map any part of the path `/var/lib/kubelet/seccomp/operator`.

### Enable CPU and memory profiling

It is possible to enable the CPU and memory profiling endpoints for debugging
purposes. To be able to utilize the profiling support, patch the spod config by
adjusting the `enableProfiling` value:

```
> kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableProfiling":true}}'
securityprofilesoperatordaemon.security-profiles-operator.x-k8s.io/spod patched
```

The containers of the daemon should now indicate that it's serving the profiling
endpoint, where every container is using a different port:

```
> k logs ds/spod -c security-profiles-operator | grep "Starting profiling"
I1202 15:14:40.276363 2185724 main.go:226]  "msg"="Starting profiling server"  "endpoint"="localhost:6060"

> k logs ds/spod -c log-enricher | grep "Starting profiling"
I1202 15:14:40.364046 2185814 main.go:226]  "msg"="Starting profiling server"  "endpoint"="localhost:6061"

> k logs ds/spod -c bpf-recorder | grep "Starting profiling"
I1202 15:14:40.457506 2185914 main.go:226]  "msg"="Starting profiling server"  "endpoint"="localhost:6062"
```

Then use the pprof tool to look at the heap profile:

```
> go tool pprof http://$PODIP:6060/debug/pprof/heap
```

Or to look at a 30-second CPU profile:

```
go tool pprof http://$PODIP:6060/debug/pprof/profile?seconds=30
```

Note that selinuxd, if enabled, doesn't set up a HTTP listener, but only
listens on a UNIX socket shared between selinuxd and the `spod` DS pod.
Nonetheless, this socket can be used to reach the profiling enpoint as
well:

```
kubectl exec spod-4pt84 -c selinuxd -- curl --unix-socket /var/run/selinuxd/selinuxd.sock http://localhost/debug/pprof/heap --output - > /tmp/heap.selinuxd
go tool pprof /tmp/heap.selinuxd
```

For a study of the facility in action, please visit:
https://blog.golang.org/2011/06/profiling-go-programs.html

### Use a custom `/proc` location for nested environments like `kind`

The operator configuration supports specifying a custom `/proc` location, which
is required for the container ID retrieval of the log-enricher as well as the
bpf-recorder. To use a custom path for `/proc`, just patch the spod accordingly:

```
kubectl patch spod spod --type=merge -p '{"spec":{"hostProcVolumePath":"/my-proc"}}'
```

## Uninstalling

To uninstall, remove the profiles before removing the rest of the operator:

```sh
$ kubectl delete seccompprofiles --all --all-namespaces
$ kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml
```
