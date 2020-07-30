# Usage

## Features

- Enables use of `ConfigMap` to store seccomp profiles.
- Synchronises seccomp profiles across all nodes.

## How To

### 1. Install operator

```sh
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/seccomp-operator/master/deploy/operator.yaml
```

### 2. Create Profile

ConfigMaps with profiles must exist within the `seccomp-operator` namespace and be
annotated with `seccomp.security.kubernetes.io/profile: "true"`. As per below:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: seccomp-operator
  name: cfg-map-name
  annotations:
    seccomp.security.kubernetes.io/profile: "true"
data:
  profile1.json: |-
    { "defaultAction": "SCMP_ACT_ERRNO" }
  profile2.json: |-
    { "defaultAction": "SCMP_ACT_LOG" }
```

The operator will get that ConfigMap and save all its profiles into the folder:

`/var/lib/kubelet/seccomp/operator/cfg-map-name/`.

### 3. Apply profile to pod

Create a pod using one of the created profiles:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/cfg-map-name/profile1.json"
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
I0618 16:08:43.507538       1 profile.go:125] profile "msg"="Reconciled profile" "namespace"="seccomp-operator" "profile"="test-profile" "resource version"="2912"
```

Confirm that the seccomp profiles are saved into the correct path:

```sh
$ kubectl exec -t -n seccomp-operator seccomp-operator-v6p2h -- ls /var/lib/kubelet/seccomp/operator/test-profile
profile-block.json
profile-complain.json
```

Please note corrupted seccomp profiles can disrupt your workloads. Therefore, ensure that the user used cannot be abused by:

- Not creating that user on the actual node.
- Restricting the user ID to only seccomp-operator (i.e. using PSP).
- Not allowing other workloads to map any part of the path `/var/lib/kubelet/seccomp/operator`.
