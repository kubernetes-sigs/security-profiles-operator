# Installation and Usage

## Features

The feature scope of the seccomp-operator is right now limited to:

- Enable `ConfigMap`s to store seccomp profiles.
- Synchronize seccomp profiles across all worker nodes.
- Validate if a node supports seccomp and do not synchronize if not.
- Validate if a profile is syntactically correct and do not synchronize if not.

## How To

### 1. Install operator

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/seccomp-operator/master/deploy/operator.yaml
```

### 2. Create Profile

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

### 3. Apply profile to pod

Create a pod using one of the created profiles:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/my-namespace/cfg-map-name/profile1.json"
spec:
  containers:
    - name: test-container
      image: nginx
```

## Troubleshooting

Confirm that the profile is being reconciled:

```sh
$ kubectl logs -n seccomp-operator seccomp-operator-v6p2h

I0618 16:06:55.242567       1 main.go:38] setup "msg"="starting seccomp-operator"
I0618 16:06:55.497098       1 listener.go:44] controller-runtime/metrics "msg"="metrics server is starting to listen"  "addr"=":8080"
I0618 16:06:55.497293       1 main.go:59] setup "msg"="starting manager"
I0618 16:06:55.498089       1 internal.go:393] controller-runtime/manager "msg"="starting metrics server"  "path"="/metrics"
I0618 16:06:55.498392       1 controller.go:164] controller-runtime/controller "msg"="Starting EventSource"  "controller"="profile" "source"={"Type":{"metadata":{"creationTimestamp":null}}}
I0618 16:06:55.598778       1 controller.go:171] controller-runtime/controller "msg"="Starting Controller"  "controller"="profile"
I0618 16:06:55.598873       1 controller.go:190] controller-runtime/controller "msg"="Starting workers"  "controller"="profile" "worker count"=1
I0618 16:08:43.507538       1 profile.go:125] profile "msg"="Reconciled profile" "namespace"="my-namespace" "profile"="test-profile" "resource version"="2912"
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
