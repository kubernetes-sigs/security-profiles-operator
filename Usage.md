# Usage

## Features

- Enables use of `ConfigMap` to store seccomp profiles.
- Synchronises seccomp profiles across all nodes.


## Installation

```sh
kubectl apply -f deploy/service-account.yaml
kubectl apply -f deploy/operator.yaml
```

## Testing

```sh
kubectl apply -f example/profile.yaml
```