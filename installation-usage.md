# Installation and Usage

## Features

The feature scope of the seccomp-operator is right now limited to:

- Enable `ConfigMap`s to store seccomp profiles.
- Synchronize seccomp profiles across all worker nodes.
- Validate if a node supports seccomp and do not synchronize if not.
- Validate if a profile is syntactically correct and do not synchronize if not.

There is now also a `SeccompProfile` Custom Resource Definition available to
validate and store seccomp profiles. This custom resource is in Alpha status and
may change at any time.

## Tutorials and Demos

- [Introduction to Seccomp and the Kubernetes Seccomp Operator](https://youtu.be/exg_zrg16SI)
  ([@saschagrunert](https://github.com/saschagrunert) and [@hasheddan](https://github.com/hasheddan))

## How To

### 1. Install operator

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/seccomp-operator/master/deploy/operator.yaml
```

### 2. Create Profile

#### ConfigMap

ConfigMaps with profiles will be separated by their target namespace and must be
annotated with `seccomp.security.kubernetes.io/profile: "true"`. As per below:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: my-namespace
  name: cfg-map-name
  annotations:
    seccomp.security.kubernetes.io/profile: "true"
data:
  profile1.json: |-
    { "defaultAction": "SCMP_ACT_ERRNO" }
  profile2.json: |-
    { "defaultAction": "SCMP_ACT_LOG" }
```

The operator will get that ConfigMap and save all its profiles into the
directory:

`/var/lib/kubelet/seccomp/operator/my-namespace/cfg-map-name/`.

An init container will setup the root directory of the operator to be able to
run it without root G/UID. This will be done by creating a symlink from the
rootless profile storage `/var/lib/seccomp-operator` to the default seccomp root
path inside of the kubelet root `/var/lib/kubelet/seccomp/operator`.

#### SeccompProfile

A `SeccompProfile` can also be used to create profiles. Example:

```yaml
apiVersion: v1alpha1
kind: SeccompProfile
metadata:
  namespace: my-namespace
  name: profile1
spec:
  defaultAction: SCMP_ACT_LOG
  ```

This seccomp profile will be saved at the path:

`/var/lib/kubelet/seccomp/operator/my-namespace/custom-profiles/profile1.json`.

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
      localhostProfile: operator/my-namespace/cfg-map-name/profile1.json
      # if using SeccompProfile:
      # localhostProfile: operator/my-namespace/custom-profiles/profile1.json
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
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/my-namespace/cfg-map-name/profile1.json"
    # if using SeccompProfile:
    # seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/my-namespace/custom-profiles/profile1.json"
spec:
  containers:
    - name: test-container
      image: nginx
```

## Restricting to a Single Namespace

The seccomp-operator can optionally be run to watch ConfigMaps in a single
namespace. This is advantageous because it allows for tightening the RBAC
permissions required by the operator's ServiceAccount. To modify the operator
deployment to run in a single namespace, use the `namespace-operator.yaml`
manifest with your namespace of choice:

```sh
NAMESPACE=<your-namespace>

curl https://raw.githubusercontent.com/kubernetes-sigs/seccomp-operator/master/deploy/namespace-operator.yaml | sed "s/NS_REPLACE/$NAMESPACE/g" | kubectl apply -f -
```

## Troubleshooting

Confirm that the profile is being reconciled:

```sh
$ kubectl logs -n seccomp-operator seccomp-operator-v6p2h

I1009 21:47:54.491462       1 main.go:90] setup "msg"="starting seccomp-operator"  "buildDate"="2020-09-30T14:37:39Z" "compiler"="gc" "gitCommit"="unknown" "gitTreeState"="clean" "goVersion"="go1.15.2" "platform"="linux/amd64" "version"="0.2.0-dev"
I1009 21:47:54.900650       1 listener.go:44] controller-runtime/metrics "msg"="metrics server is starting to listen"  "addr"=":8080"
I1009 21:47:54.902267       1 main.go:126] setup "msg"="starting manager"
I1009 21:47:54.902854       1 internal.go:391] controller-runtime/manager "msg"="starting metrics server"  "path"="/metrics"
I1009 21:47:54.903193       1 controller.go:142] controller "msg"="Starting EventSource" "controller"="profile" "reconcilerGroup"="" "reconcilerKind"="ConfigMap" "source"={"Type":{"metadata":{"creationTimestamp":null}}}
I1009 21:47:54.903342       1 controller.go:142] controller "msg"="Starting EventSource" "controller"="profile" "reconcilerGroup"="seccomp-operator.x-k8s.io" "reconcilerKind"="SeccompProfile" "source"={"Type":{"metadata":{"creationTimestamp":null},"spec":{"defaultAction":""}}}
I1009 21:47:55.003608       1 controller.go:149] controller "msg"="Starting Controller" "controller"="profile" "reconcilerGroup"="" "reconcilerKind"="ConfigMap"
I1009 21:47:55.003765       1 controller.go:149] controller "msg"="Starting Controller" "controller"="profile" "reconcilerGroup"="seccomp-operator.x-k8s.io" "reconcilerKind"="SeccompProfile"
I1009 21:47:55.003915       1 controller.go:176] controller "msg"="Starting workers" "controller"="profile" "reconcilerGroup"="seccomp-operator.x-k8s.io" "reconcilerKind"="SeccompProfile" "worker count"=1
I1009 21:47:55.003923       1 controller.go:176] controller "msg"="Starting workers" "controller"="profile" "reconcilerGroup"="" "reconcilerKind"="ConfigMap" "worker count"=1
E1009 21:47:55.004175       1 profile.go:133] profile "msg"="unable to fetch SeccompProfile" "error"="SeccompProfile.seccomp-operator.x-k8s.io \"default-profiles\" not found" "namespace"="seccomp-operator" "profile"="default-profiles"
I1009 21:47:55.005805       1 profile.go:232] profile "msg"="Reconciled profile from ConfigMap" "namespace"="seccomp-operator" "profile"="default-profiles" "name"="default-profiles" "resource version"="9907"
```

Confirm that the seccomp profiles are saved into the correct path:

```sh
$ kubectl exec -t -n seccomp-operator seccomp-operator-v6p2h -- ls /var/lib/kubelet/seccomp/operator/my-namespace/test-profile
profile-block.json
profile-complain.json
```

Please note corrupted seccomp profiles can disrupt your workloads. Therefore, ensure that the user used cannot be abused by:

- Not creating that user on the actual node.
- Restricting the user ID to only seccomp-operator (i.e. using PSP).
- Not allowing other workloads to map any part of the path `/var/lib/kubelet/seccomp/operator`.
