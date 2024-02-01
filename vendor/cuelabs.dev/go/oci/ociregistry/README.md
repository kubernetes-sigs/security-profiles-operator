# `ociregistry`

In the top level package (`ociregistry`) this module defines a [Go interface](./interface.go) that encapsulates the operations provided by an OCI
registry.

Full reference documentation can be found [here](https://pkg.go.dev/cuelabs.dev/go/oci/ociregistry).

It also provides a lightweight in-memory implementation of that interface (`ocimem`)
and an HTTP server that implements the [OCI registry protocol](https://github.com/opencontainers/distribution-spec/blob/main/spec.md) on top of it.

The server currently passes the [conformance tests](https://pkg.go.dev/github.com/opencontainers/distribution-spec/conformance).

That said, it is in total flux at the moment! Do not use it as a dependency, as the API is changing hourly.

The aim, however, is to provide an ergonomic interface for defining and layering
OCI registry implementations.

The code was originally derived from the [go-containerregistry](https://pkg.go.dev/github.com/google/go-containerregistry/pkg/registry) registry, but has considerably diverged since then.
