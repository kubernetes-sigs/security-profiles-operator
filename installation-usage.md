# Installation and Usage

## Features

The feature scope of the security-profiles-operator is right now limited to:

- Adds a `SeccompProfile` CRD (alpha) to store seccomp profiles.
- Synchronize seccomp profiles across all worker nodes.
- Validate if a node supports seccomp and do not synchronize if not.

## Tutorials and Demos

- [Introduction to Seccomp and the Kubernetes Seccomp Operator](https://youtu.be/exg_zrg16SI)
  ([@saschagrunert](https://github.com/saschagrunert) and [@hasheddan](https://github.com/hasheddan))

## How To

### 1. Install operator

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/operator.yaml
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/profiles/default-profiles.yaml
```

### 2. Create Profile

Use the `SeccompProfile` kind to create profiles. Example:

```yaml
apiVersion: v1alpha1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
  targetWorkload: custom-profiles
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

#### Base syscalls for a container runtime

An example of the minimum required syscalls for a runtime such as runc (tested
on version 1.0.0-rc92) to launch a container can be found in [the
examples](./examples/baseprofile.yaml). You can use this example as a starting
point for creating custom profiles for your application. You can also
programmatically combine it with your custom profiles in order to build
application-specific profiles that only specify syscalls that are required on
top of the base calls needed for the container runtime. For example:

```yaml
apiVersion: v1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_ERRNO
  targetWorkload: custom-profiles
  baseProfileName: runc-v1.0.0-rc92
  syscalls:
  - action: SCMP_ACT_ALLOW
    names:
    - exit_group
```

## Restricting to a Single Namespace

The security-profiles-operator can optionally be run to watch SeccompProfiles in
a single namespace. This is advantageous because it allows for tightening the
RBAC permissions required by the operator's ServiceAccount. To modify the
operator deployment to run in a single namespace, use the
`namespace-operator.yaml` manifest with your namespace of choice:

```sh
NAMESPACE=<your-namespace>

curl https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/namespace-operator.yaml | sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
curl https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/profiles/namespace-default-profiles.yaml | sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
```

## Troubleshooting

Confirm that the profile is being reconciled:

```sh
$ kubectl -n security-profiles-operator logs security-profiles-operator-mzw9t
I1019 19:34:14.942464       1 main.go:90] setup "msg"="starting security-profiles-operator"  "buildDate"="2020-10-19T19:31:24Z" "compiler"="gc" "gitCommit"="a3ef0e1ea6405092268c18f240b62015c247dd9d" "gitTreeState"="dirty" "goVersion"="go1.15.1" "platform"="linux/amd64" "version"="0.2.0-dev"
I1019 19:34:15.348389       1 listener.go:44] controller-runtime/metrics "msg"="metrics server is starting to listen"  "addr"=":8080"
I1019 19:34:15.349076       1 main.go:126] setup "msg"="starting manager"
I1019 19:34:15.349449       1 internal.go:391] controller-runtime/manager "msg"="starting metrics server"  "path"="/metrics"
I1019 19:34:15.350201       1 controller.go:142] controller "msg"="Starting EventSource" "controller"="profile" "reconcilerGroup"="security-profiles-operator.x-k8s.io" "reconcilerKind"="SeccompProfile" "source"={"Type":{"metadata":{"creationTimestamp":null},"spec":{"targetWorkload":"","defaultAction":""}}}
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
$ kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/profiles/default-profiles.yaml
$ kubectl delete -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/master/deploy/operator.yaml
```
