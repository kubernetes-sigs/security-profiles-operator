[Installation and Usage](installation-usage.md) | [Installation](installation.md) | [Profiles](profiles.md) | [CLI](cli.md) | [Metrics](metrics.md) | **Troubleshooting**

<!-- toc -->
- [Troubleshooting](#troubleshooting)
  - [Enable CPU and memory profiling](#enable-cpu-and-memory-profiling)
  - [Use a custom <code>/proc</code> location for nested environments like <code>kind</code>](#use-a-custom-proc-location-for-nested-environments-like-kind)
  - [Notes on OpenShift and SCCs](#notes-on-openshift-and-sccs)
    - [SELinux recording should allow <code>seLinuxContext: RunAsAny</code>](#selinux-recording-should-allow-selinuxcontext-runasany)
    - [Replicating controllers and SCCs](#replicating-controllers-and-sccs)
- [Uninstalling](#uninstalling)
<!-- /toc -->

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
$ kubectl exec -t -n security-profiles-operator security-profiles-operator-v6p2h -- ls /var/lib/kubelet/seccomp/operator/my-workload
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
> k logs --selector name=spod -c security-profiles-operator | grep "Starting profiling"
I1202 15:14:40.276363 2185724 main.go:226]  "msg"="Starting profiling server"  "endpoint"="localhost:6060"

> k logs --selector name=spod -c log-enricher | grep "Starting profiling"
I1202 15:14:40.364046 2185814 main.go:226]  "msg"="Starting profiling server"  "endpoint"="localhost:6061"

> k logs --selector name=spod -c bpf-recorder | grep "Starting profiling"
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
Nonetheless, this socket can be used to reach the profiling endpoint as
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
    type: test-selinux-recording-nginx-0_nginx-secure.process
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
the serviceAccount it is supposed to be used by. Please refer to the [OCP documentation](https://docs.openshift.com/container-platform/4.9/authentication/managing-security-context-constraints.html)
or [this Red Hat blog post](https://cloud.redhat.com/blog/managing-sccs-in-openshift) for more information
on managing SCCs.

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

To uninstall, remove the profiles before removing the rest of the operator:

```sh
$ kubectl delete seccompprofiles --all
$ kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/main/deploy/operator.yaml
```
