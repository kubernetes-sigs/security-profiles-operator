[Documentation](README.md) | [Installation](installation.md) | [Profiles](profiles.md) | [CLI](cli.md) | [Metrics](metrics.md) | **Troubleshooting**

<!-- toc -->
- [Troubleshooting](#troubleshooting)
  - [The operator runs but no <code>spod</code> DaemonSet appears](#the-operator-runs-but-no-spod-daemonset-appears)
  - [Enable CPU and memory profiling](#enable-cpu-and-memory-profiling)
  - [Use a custom <code>/proc</code> location for nested environments like <code>kind</code>](#use-a-custom-proc-location-for-nested-environments-like-kind)
  - [Notes on OpenShift and SCCs](#notes-on-openshift-and-sccs)
    - [SELinux recording should allow <code>seLinuxContext: RunAsAny</code>](#selinux-recording-should-allow-selinuxcontext-runasany)
    - [Replicating controllers and SCCs](#replicating-controllers-and-sccs)
- [Uninstalling](#uninstalling)
<!-- /toc -->

## Troubleshooting

Confirm that the profile is installed. The operator aggregates the state of
every node into the profile status:

```sh
$ kubectl get seccompprofiles
NAME            STATUS      AGE
profile-block   Installed   2m
```

The state of each node is available from the `SecurityProfileNodeStatus`
objects, which also point to the node that failed if the profile is not
installed everywhere:

```sh
$ kubectl get securityprofilenodestatuses -o wide
NAME                            STATUS      AGE   NODE
profile-block-node-1            Installed   2m    node-1
```

The events of the profile carry the error message of a failed installation:

```sh
kubectl describe seccompprofile profile-block
```

The `spod` daemon installs the profiles on each node, so its logs show how
the profile got reconciled:

```sh
kubectl -n security-profiles-operator logs ds/spod -c security-profiles-operator
```

Seccomp profiles are cluster scoped and the daemon writes them to
`/var/lib/kubelet/seccomp/operator` on every node. Confirm that the profile
files exist:

```sh
$ kubectl -n security-profiles-operator exec ds/spod -c security-profiles-operator -- ls /var/lib/kubelet/seccomp/operator
profile-block.json
profile-complain.json
```

Please note that corrupted seccomp profiles can disrupt your workloads.
Therefore, do not allow other workloads to write to any part of the path
`/var/lib/kubelet/seccomp/operator` on the nodes.

### The operator runs but no `spod` DaemonSet appears

An operator Deployment which reports `Running` can still be doing nothing at
all. The manager waits for every informer cache before it starts a single
controller, and that wait has no timeout, so one resource it is not allowed to
list stops `spod` from ever being created. The
`SecurityProfilesOperatorDaemon` then stays without a state:

```sh
$ kubectl -n security-profiles-operator get ds
No resources found in security-profiles-operator namespace.

$ kubectl get securityprofilesoperatordaemons -A
NAMESPACE                    NAME   STATE
security-profiles-operator   spod
```

The manager log names the resource, repeating every few seconds:

```
E0918 14:49:17.170072 1 runtime.go:252] "Failed to watch" err="failed to list *v1.ProfileBinding: profilebindings.security-profiles-operator.x-k8s.io is forbidden: User \"system:serviceaccount:security-profiles-operator:security-profiles-operator\" cannot list resource \"profilebindings\" in API group \"security-profiles-operator.x-k8s.io\" at the cluster scope" logger="controller-runtime.cache.UnhandledError"
```

The operator reports this state through its readiness probe, so its pods stay
`0/1` ready while the caches do not sync.

A missing permission like that means the deployed RBAC is older than the
operator image, which happens when the two come from different versions. Verify
that the manifests and the image belong together, for example that a Helm
install did not leave `spoImage.tag` at `latest`:

```sh
kubectl -n security-profiles-operator get deploy security-profiles-operator \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

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
> kubectl -n security-profiles-operator logs --selector name=spod -c security-profiles-operator | grep "Starting profiling"
I1202 15:14:40.276363 2185724 main.go:226]  "msg"="Starting profiling server"  "endpoint"=":6060"

> kubectl -n security-profiles-operator logs --selector name=spod -c log-enricher | grep "Starting profiling"
I1202 15:14:40.364046 2185814 main.go:226]  "msg"="Starting profiling server"  "endpoint"=":6061"

> kubectl -n security-profiles-operator logs --selector name=spod -c bpf-recorder | grep "Starting profiling"
I1202 15:14:40.457506 2185914 main.go:226]  "msg"="Starting profiling server"  "endpoint"=":6062"
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
Nonetheless, this socket can be used to reach the profiling endpoint as
well:

```
kubectl exec spod-4pt84 -c selinuxd -- curl --unix-socket /var/run/selinuxd/selinuxd.sock http://localhost/debug/pprof/heap --output - > /tmp/heap.selinuxd
go tool pprof /tmp/heap.selinuxd
```

For a study of the facility in action, please visit:
https://go.dev/blog/pprof

### Use a custom `/proc` location for nested environments like `kind`

The operator configuration supports specifying a custom `/proc` location, which
is required for the container ID retrieval of the log-enricher as well as the
bpf-recorder. The path has to be `/proc` or a directory below it, for example
`/proc/host`. To use a custom path for `/proc`, patch the spod accordingly:

```
kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"hostProcVolumePath":"/proc/host"}}'
```

### Notes on OpenShift and SCCs

There are several things particular to OpenShift that are useful to be aware of when
deploying and recording security profiles, mostly coming from OpenShift's default use
of SCCs.

#### SELinux recording should allow `seLinuxContext: RunAsAny`

Recording of SELinux policies is implemented with a webhook that injects a special SELinux
type to the pods being recorded. This type makes the pod run in "permissive" mode, logging
all the AVC denials into `audit.log`. By default, especially with the more restrictive SCCs,
a workload is not allowed to run with a custom SELinux policy, but uses an autogenerated type.

Therefore in order to record a workload, the workload must use a service account that is allowed
to use an SCC that allows the webhook to inject this permissive type into it. This can be achieved
by using any SCC that uses `seLinuxContext: RunAsAny`, including the `privileged` SCC shipped
by default with OpenShift.

In addition, the namespace must be labeled with
`pod-security.kubernetes.io/enforce: privileged` if your cluster enables the
[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
because only the `privileged`
[Pod Security Standard](https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged)
allows running with a custom SELinux policy. In contrast, even the `restricted` Pod Security Standard
allows the use of `Localhost` seccomp profiles.

#### Replicating controllers and SCCs

When deploying SELinux policies for replicating controllers (deployments,
daemonsets, ...), note that the pods that these controllers spawn are not running with the identity
of the user who creates the workload. Unless a `ServiceAccount` is selected, this means that the pods
might fall back to using one of the secure but restricted SCCs which don't allow to use a custom SELinux
policy.

One option is to use an SCC with `seLinuxContext: RunAsAny`, but it's
more secure to only restrict your workloads to the security profiles they should be using.

Taking the SELinux policy we recorded earlier for an nginx deployment as an
example, we might create the following SCC which is based on the `restricted`
SCC shipped in OpenShift, just allows our SELinux policy to be used.
Note that we'll be deploying in the `nginx-secure` namespace, as you can
see from the ServiceAccount name we are putting into the `users` array.

```yaml
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  annotations:
    kubernetes.io/description: A special SCC for running nginx with a custom SELinux policy
  name: nginx-secure
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
allowedCapabilities: null
defaultAddCapabilities: null
fsGroup:
  type: MustRunAs
priority: null
readOnlyRootFilesystem: false
requiredDropCapabilities:
  - KILL
  - MKNOD
  - SETUID
  - SETGID
runAsUser:
  type: MustRunAsRange
seLinuxContext:
  type: MustRunAs
  seLinuxOptions:
    type: test-selinux-recording-nginx-0.process
supplementalGroups:
  type: RunAsAny
users:
  - system:serviceaccount:nginx-secure:nginx-sa
volumes:
  - configMap
  - downwardAPI
  - emptyDir
  - persistentVolumeClaim
  - projected
  - secret
```

Please note that a common mistake when creating custom SCCs is to bind them to a wide range of users or SAs
through the `group` attribute, e.g. the `system:authenticated` group. Make sure your SCC is only usable by
the serviceAccount it is supposed to be used by. Please refer to the [OpenShift documentation on managing SCCs](https://docs.redhat.com/en/documentation/openshift_container_platform/4.19/html/authentication_and_authorization/managing-pod-security-policies)
for more information.

Then we create the appropriate role:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: nginx
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
```

and finally a role binding and the SA.

With all that set up, we can finally create our deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deployment
spec:
  selector:
    matchLabels:
      app: nginx
  replicas: 2
  template:
    metadata:
      labels:
        app: nginx
    spec:
      serviceAccountName: nginx-sa
      containers:
        - name: nginx
          image: nginxinc/nginx-unprivileged:1.21
```

Note that we don't specify the SELinux type at all in the workload, that's handled by the SCC instead.
When the pods are created through the deployment and its `ReplicaSet`, they should be
running with the appropriate profile.

## Uninstalling

To uninstall, remove the bindings, recordings and profiles before removing the
rest of the operator, so that the operator can remove the installed profiles
from the nodes:

```sh
kubectl delete profilebindings --all --all-namespaces
kubectl delete profilerecordings --all --all-namespaces
kubectl delete seccompprofiles --all
kubectl delete selinuxprofiles --all
kubectl delete rawselinuxprofiles --all
kubectl delete apparmorprofiles --all
```

Profiles that are still used by running pods are only removed once those pods
are gone. Then remove the operator with the manifest it was installed from,
where `VERSION` is the installed release version, for example `1.1.0`:

```sh
kubectl delete -f "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/operator.yaml"
```

For Helm and OLM installations, use `helm uninstall` or remove the
`Subscription` and `ClusterServiceVersion` instead. Neither removes the CRDs,
which can be deleted afterwards if no profiles should be kept:

```sh
kubectl get crds -o name | grep security-profiles-operator.x-k8s.io | xargs kubectl delete
```

The admission policies which the operator creates at runtime are not part of
any manifest, so remove them as well:

```sh
kubectl delete validatingadmissionpolicies,validatingadmissionpolicybindings -l app=security-profiles-operator
```
