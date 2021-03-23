# Installation and Usage

## Features

The feature scope of the security-profiles-operator is right now limited to:

- Adds a `SeccompProfile` CRD (alpha) to store seccomp profiles.
- Adds a `ProfileBinding` CRD (alpha) to bind security profiles to pods.
- Adds a `ProfileRecording` CRD (alpha) to record security profiles from workloads.
- Synchronize seccomp profiles across all worker nodes.
- Validates if a node supports seccomp and do not synchronize if not.

## Tutorials and Demos

- [Introduction to Seccomp and the Kubernetes Seccomp Operator](https://youtu.be/exg_zrg16SI)
  ([@saschagrunert](https://github.com/saschagrunert) and [@hasheddan](https://github.com/hasheddan))

## How To

### 1. Install operator

The operator container image consists of an image manifest which supports the
architectures `amd64` and `arm64` for now. To deploy the operator, first install
cert-manager via `kubectl`:

```sh
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml
$ kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager
```

Then apply the operator manifest:

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/operator.yaml
```

### 2. Create Profile

Use the `SeccompProfile` kind to create profiles. Example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
```

This seccomp profile will be saved at the path:

`/var/lib/kubelet/seccomp/operator/my-namespace/custom-profiles/profile1.json`.

An init container will set up the root directory of the operator to be able to
run it without root G/UID. This will be done by creating a symlink from the
rootless profile storage `/var/lib/security-profiles-operator` to the default seccomp root
path inside of the kubelet root `/var/lib/kubelet/seccomp/operator`.

### 3. Apply profile to pod

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
      localhostProfile: operator/my-namespace/custom-profiles/profile1.json
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
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/my-namespace/custom-profiles/profile1.json"
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
profile1   Active   14s   operator/my-namespace/custom-profiles/profile1.json
```

You can apply the profile to an existing application, such as a Deployment or
Daemonset:

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
    "localhostProfile": "operator/my-namespace/custom-profiles/profile1.json",
    "type": "Localhost"
  }
}
```

#### Base syscalls for a container runtime

An example of the minimum required syscalls for a runtime such as
[runc](https://github.com/opencontainers/runc) (tested on version 1.0.0-rc92) to
launch a container can be found in [the
examples](./examples/baseprofile-runc.yaml). You can use this example as a
starting point for creating custom profiles for your application. You can also
programmatically combine it with your custom profiles in order to build
application-specific profiles that only specify syscalls that are required on
top of the base calls needed for the container runtime. For example:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  baseProfileName: runc-v1.0.0-rc92
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - exit_group
```

If you're not using runc but the alternative
[crun](https://github.com/containers/crun), then you can do the same by using
the [corresponding example profile](./examples/baseprofile-crun.yaml) (tested
with version 0.17).

#### Bind workloads to profiles with ProfileBindings

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

#### Record profiles from workloads with ProfileRecordings

The operator is capable of recording seccomp profiles by the usage of the
[oci-seccomp-bpf-hook][bpf-hook]. [OCI hooks][hooks] are part of the OCI
runtime-spec, which allow to hook into the container creation process. The
Kubernetes container runtime [CRI-O][cri-o] supports those hooks out of the box,
but has to be configured to listen on the hooks directory where the
[oci-seccomp-bpf-hook.json][hook-json] located. This can be done via a drop-in
configuration file, for example:

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

We can create a new `ProfileRecording` to indicate to the operator that a
specific workload should be recorded:

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: ProfileRecording
metadata:
  name: test-recording
spec:
  kind: SeccompProfile
  podSelector:
    matchLabels:
      app: alpine
```

This means that every workload which contains the label `app=alpine` will from
now on be recorded into the `SeccompProfile` CRD with the name `test-recording`.
Please be aware that the resource will be overwritten if recordings are executed
multiple times.

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

## Restricting to a Single Namespace

The security-profiles-operator can optionally be run to watch SeccompProfiles in
a single namespace. This is advantageous because it allows for tightening the
RBAC permissions required by the operator's ServiceAccount. To modify the
operator deployment to run in a single namespace, use the
`namespace-operator.yaml` manifest with your namespace of choice:

```sh
NAMESPACE=<your-namespace>

curl https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/namespace-operator.yaml | sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
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

## Uninstalling

To uninstall, remove the profiles before removing the rest of the operator:

```sh
$ kubectl delete seccompprofiles --all --all-namespaces
$ kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/operator.yaml
```
