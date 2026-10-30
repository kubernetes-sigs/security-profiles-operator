# Troubleshooting

[Documentation](README.md) | [Installation](installation.md) | [Configuration](configuration.md) | [Profiles](profiles.md) | [Recording](recording.md) | [CLI](cli.md) | [Metrics](metrics.md) | **Troubleshooting**

<!-- toc -->
- [Check the state of a profile](#check-the-state-of-a-profile)
- [The operator runs but no <code>spod</code> DaemonSet appears](#the-operator-runs-but-no-spod-daemonset-appears)
- [Enable CPU and memory profiling](#enable-cpu-and-memory-profiling)
- [Notes on OpenShift and SCCs](#notes-on-openshift-and-sccs)
  - [SELinux recording should allow <code>seLinuxContext: RunAsAny</code>](#selinux-recording-should-allow-selinuxcontext-runasany)
  - [Replicating controllers and SCCs](#replicating-controllers-and-sccs)
<!-- /toc -->

## Check the state of a profile

Confirm that the profile is installed. The operator aggregates the state of
every node into the profile status:

```console
$ kubectl get seccompprofiles
NAME                STATUS      AGE
profile-block-all   Installed   2m
```

The state of each node is available from the `SecurityProfileNodeStatus`
objects, which also point to the node that failed if the profile is not
installed everywhere:

```console
$ kubectl get securityprofilenodestatuses -o wide
NAME                                      STATUS      AGE   NODE
seccompprofile-profile-block-all-node-1   Installed   2m    node-1
```

The `status.message` of a node status tells why the profile failed on that
node:

```shell
kubectl get securityprofilenodestatuses -l spo.x-k8s.io/profile-id=SeccompProfile-profile-block-all \
  -o custom-columns=NODE:.spec.nodeName,STATUS:.status.status,MESSAGE:.status.message
```

A node whose daemon pod is not available, for example because the node is not
ready or the pod crashes, does not hold back the state of the profile: the
profile gets the state of the other nodes, and the message of its `Ready`
condition names the nodes it leaves out. The profile may be missing on these
nodes, so pods using it fail to start there until the daemon pod recovers. An
installed profile then has the `Ready` condition reason
`InstalledOnAvailableNodes` instead of `Available`, and gets a warning event
with the same reason whenever the nodes it leaves out change:

```shell
kubectl get seccompprofiles \
  -o custom-columns=NAME:.metadata.name,STATUS:.status.status,REASON:'.status.conditions[?(@.type=="Ready")].reason'
```

A node which does not support the kind of the profile, like a node without
AppArmor in a cluster with `enableAppArmor`, reports a node status with the
`spo.x-k8s.io/kind-unsupported` label, whose `status.message` tells why. The
state of the profile leaves these nodes out, and the message of its `Ready`
condition names them. Pods using the profile fail to start on these nodes. If
no node supports the kind, the profile gets the state of these node statuses,
like `Error`. To list the nodes which do not support a profile:

```shell
kubectl get securityprofilenodestatuses -l spo.x-k8s.io/kind-unsupported \
  -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,MESSAGE:.status.message
```

The events of the profile carry the error message of a failed installation:

```shell
kubectl describe seccompprofile profile-block-all
```

The daemon installs the profiles on each node, so its logs show how the
profile got reconciled:

```shell
kubectl -n security-profiles-operator logs ds/spod -c security-profiles-operator
```

Seccomp profiles are cluster scoped and the daemon writes them to
`/var/lib/kubelet/seccomp/operator` on every node, or below the
[custom kubelet root directory](configuration.md#configure-a-custom-kubelet-root-directory)
of the node. The operator image has no shell or `ls`, so confirm that the
profile files exist from a debug pod on the node, which mounts the root of the
node at `/host`:

```console
$ kubectl debug node/<node> -it --image=busybox -- chroot /host ls /var/lib/kubelet/seccomp/operator
profile-block-all.json
profile-complain-unsafe.json
```

`kubectl debug` leaves the `node-debugger-*` pod behind, delete it afterwards.

Corrupted seccomp profiles can disrupt your workloads. Therefore, do not allow
other workloads to write to any part of the path
`/var/lib/kubelet/seccomp/operator` on the nodes.

## The operator runs but no `spod` DaemonSet appears

Running operator pods can still be doing nothing at all. The manager waits for
every informer cache before it starts a single controller, and that wait has no
timeout, so one resource it is not allowed to list stops the `spod` DaemonSet
from ever being created. The SPOD then stays without a state:

```console
$ kubectl -n security-profiles-operator get ds
No resources found in security-profiles-operator namespace.

$ kubectl get securityprofilesoperatordaemons -A
NAMESPACE                    NAME   STATE   READY   AGE
security-profiles-operator   spod                   5m
```

The manager log names the resource, repeating every few seconds:

```text
"Failed to watch" err="failed to list *v1.ProfileBinding: profilebindings.security-profiles-operator.x-k8s.io is forbidden: User \"system:serviceaccount:security-profiles-operator:security-profiles-operator\" cannot list resource \"profilebindings\" in API group \"security-profiles-operator.x-k8s.io\" at the cluster scope" logger="controller-runtime.cache.UnhandledError"
```

The operator reports this state through its readiness probe, so its pods stay
`0/1` ready while the caches do not sync.

A missing permission like that means the deployed RBAC is older than the
operator image, which happens when the two come from different versions. Verify
that the manifests and the image belong together, for example that a Helm
install did not leave `spoImage.tag` at `latest`:

```shell
kubectl -n security-profiles-operator get deploy security-profiles-operator \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

## Enable CPU and memory profiling

The containers of the daemon can serve the CPU and memory profiling endpoints
for debugging purposes. To enable them, set `enableProfiling` in the SPOD:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableProfiling":true}}'
```

Every container of the daemon uses a different port, `6060` plus the index of
the container in the `spod` pod. The containers depend on the enabled
features, so the port of a container can differ between clusters. The
`SPO_PROFILING_PORT` of the containers lists them, here with SELinux and the
log enricher enabled:

```console
$ kubectl -n security-profiles-operator get ds spod -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{" "}{.env[?(@.name=="SPO_PROFILING_PORT")].value}{"\n"}{end}'
security-profiles-operator 6060
selinuxd
log-enricher 6062
```

The containers log the endpoint once at their start, so `--tail=-1` reads the
whole log instead of its last lines:

```console
$ kubectl -n security-profiles-operator logs --selector name=spod -c security-profiles-operator --tail=-1 | grep "Starting profiling"
"Starting profiling server" endpoint="0.0.0.0:6060"
```

Then use the pprof tool to look at the heap profile:

```shell
go tool pprof http://$PODIP:6060/debug/pprof/heap
```

Or to look at a 30-second CPU profile:

```shell
go tool pprof "http://$PODIP:6060/debug/pprof/profile?seconds=30"
```

The profiling endpoint enabled by `--profiling` or `SPO_PROFILING` listens on
`127.0.0.1` by default, so the unauthenticated pprof handlers are not
reachable from the pod network. Use `--profiling-address` or the
`SPO_PROFILING_ADDRESS` environment variable to bind it elsewhere. The
containers of the daemon get `SPO_PROFILING_ADDRESS=0.0.0.0` when
`spec.enableProfiling` is set, so their endpoints stay reachable from the pod
network as shown above. The port still comes from `--profiling-port` or
`SPO_PROFILING_PORT` (default `6060`).

`enableProfiling` only applies to the daemon. To profile the operator pods
themselves, set `SPO_PROFILING=true` in their
[environment](configuration.md#environment-variables-of-the-operator), and
reach the endpoint on `127.0.0.1` through a port forward:

```shell
kubectl -n security-profiles-operator port-forward deploy/security-profiles-operator 6060
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

selinuxd, if enabled, doesn't set up an HTTP listener, but only listens on a
UNIX socket shared between selinuxd and the daemon. This socket can be used to
reach the profiling endpoint as well:

```shell
kubectl -n security-profiles-operator exec spod-4pt84 -c selinuxd -- curl --unix-socket /var/run/selinuxd/selinuxd.sock http://localhost/debug/pprof/heap --output - > /tmp/heap.selinuxd
go tool pprof /tmp/heap.selinuxd
```

For a study of the facility in action, see <https://go.dev/blog/pprof>.

## Notes on OpenShift and SCCs

There are several things particular to OpenShift that are useful to be aware
of when deploying and recording security profiles, mostly coming from
OpenShift's default use of SCCs.

### SELinux recording should allow `seLinuxContext: RunAsAny`

Recording of SELinux policies is implemented with a webhook that injects a
special SELinux type to the pods being recorded. This type makes the pod run in
"permissive" mode, logging all the AVC denials into `audit.log`. By default,
especially with the more restrictive SCCs, a workload is not allowed to run
with a custom SELinux policy, but uses an autogenerated type.

Therefore in order to record a workload, the workload must use a service
account that is allowed to use an SCC that allows the webhook to inject this
permissive type into it. This can be achieved by using any SCC that uses
`seLinuxContext: RunAsAny`, including the `privileged` SCC shipped by default
with OpenShift.

In addition, the namespace must be labeled with
`pod-security.kubernetes.io/enforce: privileged` if your cluster enables the
[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
because only the `privileged`
[Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged)
allows running with a custom SELinux policy. In contrast, even the `restricted`
Pod Security Standard allows the use of `Localhost` seccomp profiles.

### Replicating controllers and SCCs

When deploying SELinux policies for replicating controllers (deployments,
daemonsets, ...), note that the pods that these controllers spawn are not
running with the identity of the user who creates the workload. Unless a
`ServiceAccount` is selected, this means that the pods might fall back to using
one of the secure but restricted SCCs which don't allow to use a custom SELinux
policy.

One option is to use an SCC with `seLinuxContext: RunAsAny`, but it's more
secure to restrict your workloads to the security profiles they should be
using, with an SCC of their own which only allows their SELinux type. See
[Use a SELinux profile on OpenShift](profiles.md#use-a-selinux-profile-on-openshift)
for an example.
