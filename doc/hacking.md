# Developing SPO

This document describes how to build, install and test SPO for development
purposes. It is not exhaustive, knowledge of how an operator works is
presumed and PRs are always welcome.

<!-- toc -->
- [Building SPO locally](#building-spo-locally)
  - [Other build targets](#other-build-targets)
- [Verifying changes](#verifying-changes)
  - [Pre-commit hooks](#pre-commit-hooks)
  - [Dependencies](#dependencies)
- [Submitting a pull request](#submitting-a-pull-request)
- [Vulnerability checks and assessments](#vulnerability-checks-and-assessments)
- [Running unit tests and viewing coverage](#running-unit-tests-and-viewing-coverage)
  - [Running the unit tests of a package](#running-the-unit-tests-of-a-package)
  - [Integration tests with envtest](#integration-tests-with-envtest)
  - [Fuzz tests](#fuzz-tests)
  - [Mocking interfaces with counterfeiter](#mocking-interfaces-with-counterfeiter)
- [Installing SPO to your cluster from source](#installing-spo-to-your-cluster-from-source)
  - [Distribution specific instructions: OpenShift](#distribution-specific-instructions-openshift)
  - [Tearing down your test environment](#tearing-down-your-test-environment)
- [Running e2e tests](#running-e2e-tests)
  - [Running a single test case](#running-a-single-test-case)
  - [Sharding the test cases](#sharding-the-test-cases)
  - [Quarantined test cases](#quarantined-test-cases)
  - [Failure diagnostics](#failure-diagnostics)
  - [Running the Ubuntu e2e tests on kubernix](#running-the-ubuntu-e2e-tests-on-kubernix)
  - [Running the Fedora e2e tests on a local VM](#running-the-fedora-e2e-tests-on-a-local-vm)
  - [The Debian and Flatcar VMs](#the-debian-and-flatcar-vms)
  - [Running the spoc e2e tests](#running-the-spoc-e2e-tests)
- [Adding support for a new cluster type](#adding-support-for-a-new-cluster-type)
- [Building the operator image with support for AppArmor](#building-the-operator-image-with-support-for-apparmor)
<!-- /toc -->

## Building SPO locally

Even though SPO is a Kubernetes operator and as such is normally not meant to
be used locally, but rather deployed in a cluster from pre-built images,
it's often useful to be able to run a quick build or a test on your local machine.

Depending on what OS and version you are developing on and what features you
want to build with, you might need to either install extra dependencies or
disable features that would require them.

There are two optional features at build time:

- eBPF based recording
  - This feature requires the libbpf release which
    [`dependencies.yaml`](../dependencies.yaml) tracks for libbpfgo, and
    `libelf`, `libz` and `libzstd`, which the build links as well.
  - Install the libraries of your build OS, for example the RPMs
    `elfutils-libelf-devel`, `zlib-devel`, `libzstd-devel` and
    `libbpf-devel` on Fedora. If the libbpf of the distribution is older,
    [`hack/install-libbpf.sh`](../hack/install-libbpf.sh) builds and installs
    the tracked release, like the development container and the Debian test
    VM do.
  - Disable it with `BPF_ENABLED=0`.
- AppArmor
  - This feature requires the AppArmor headers and development libraries as
    well as the `go-apparmor` bindings.
  - Disable it with `APPARMOR_ENABLED=0`.

Technically, SELinux is also an optional feature, but since the SELinux
functionality itself is offloaded to [selinuxd](https://github.com/containers/selinuxd),
there's nothing to switch on or off at SPO build time.

If there's any additional optional features, most likely they're going to
be controlled with a similar variable, searching the Makefile for `_ENABLED`
should find them.

In addition, `libseccomp` is a hard dependency, with the only exception being
local builds on macOS, because seccomp is a Linux-only feature. Nonetheless,
for actually deploying the operator, `libseccomp` is not optional and whether
to build against seccomp is determined automatically based on the build
platform.

`make verify-format` needs `clang-format` from `clang-tools-extra`, see
[verifying changes](#verifying-changes).

To build SPO with all the features simply run:

```shell
make
```

To disable features, prefix `make` with environment variables that deselect them:

```shell
BPF_ENABLED=0 APPARMOR_ENABLED=0 make
```

In most cases you will need a container image. You can build by running:

```shell
make image
```

The default `Dockerfile` builds the operator with nix, which always includes
eBPF and AppArmor support, so `BPF_ENABLED` and `APPARMOR_ENABLED` have no
effect on `make image`. `Dockerfile.ubi` builds without both features, unless
the `BPF_ENABLED=1` and `APPARMOR_ENABLED=1` build arguments are passed to the
container build directly.

### Other build targets

`make help` lists the targets with a description. Besides the ones above:

- `make nix` builds the binaries for amd64, arm64 and ppc64le with
  [Nix](https://nixos.org/download) into `build.tar.gz`, `make nix-amd64`,
  `make nix-arm64` and so on build a single architecture. `make nix-s390x`
  exists, but the nix toolchain it needs is broken, which is why `make nix`
  leaves it out. `make nix-spoc` builds `spoc` for these architectures and
  s390x like a release, which includes generating the SBOMs with `bom` and
  signing the binaries and SBOMs keylessly with `cosign`, so it needs both
  tools on the host. The signing asks for an OIDC identity and records the
  signatures in the public Rekor transparency log, so use
  `make nix-spoc-<arch>` to only build `spoc` for a single architecture.
  Apart from that, Nix needs no native libraries on the host, and
  `make update-nixpkgs` updates its pinned package set.
- `make update-bpf` rebuilds the committed BPF objects of the recorder and the
  enricher for amd64 and arm64 with Nix, after changing the BPF programs.
  `make update-vmlinux` regenerates the `vmlinux.h` they build against.
  `make verify-bpf` checks that the committed objects are up to date.
- `make bundle` regenerates the OLM bundle below `bundle/` from the deployment
  manifests, `make verify-bundle` checks that it is up to date.
- `make manifests`, `make generate` and `make deployments` regenerate the CRDs,
  the generated code and the deployment manifests after API changes.
- [`hack/update-selinuxd.sh`](../hack/update-selinuxd.sh) pins the selinuxd
  images to the current digest of their `latest` tag in the kustomize
  deployment, the Helm values and `dependencies.yaml`, and the selinuxd
  commit which the Fedora e2e job builds to the head of the selinuxd main
  branch. Run `make deployments bundle` afterwards to regenerate the
  manifests. `hack/update-selinuxd.sh --check` only reports moved tags and a
  newer commit, which the weekly selinuxd job of the dependencies workflow
  does.
- `make update-docs` regenerates the command line reference of `spoc` and the
  operator binary below [`reference/`](reference/) after changing their flags,
  `make verify-docs` checks that it is up to date.
- `make update-proto` regenerates the gRPC code below `api/grpc` after
  changing its protocol definitions, `make verify-proto` checks that it is up
  to date.
- `make update-toc` updates the table of contents of every document with a
  `<!-- toc -->` marker after changing its headings, `make verify-toc` checks
  that they are up to date.

`nix develop` opens a shell with the Go toolchain, the C libraries of the
build and the tools of the Makefile targets (clang and llvm for the BPF
programs, protobuf, shellcheck, helm, kind, kubectl, jq and yq), so the build
with all features works without installing anything on the host. The binary
caches don't have every package of the shell, so its first start can compile
large parts of it from source, which takes hours. The repository also has a
[development container](../.devcontainer/devcontainer.json) with Go and Nix,
for editors which support it. Without the native libraries listed above, use
the Nix targets or disable the optional features.

## Verifying changes

`make verify` runs all checks which need no cluster, each of which is a target
of its own. The linters get downloaded into `build/` with pinned versions and
checksums, so no local installation is needed, except for `clang-format`.
Besides the checks of the code, the generated files and the dependencies,
these are:

- `make verify-format` formats the C and protobuf sources with the
  `clang-format` of the host. The Prow job installs the major version
  `CLANG_FORMAT_VERSION` of the `Makefile`. Other major versions may format
  differently, so the target warns about them, and a resulting diff may stem
  from the version rather than the change. `CLANG_FORMAT` selects another
  binary, like `make verify-format CLANG_FORMAT=clang-format-<version>`.
- `make verify-shellcheck` checks the shell scripts with shellcheck.
- `make verify-dockerfiles` lints the Dockerfiles with hadolint and checks that
  `Dockerfile` and `Dockerfile.ubi` did not drift apart.
- `make verify-manifests` validates the committed manifests and the examples
  against the schemas of the oldest supported Kubernetes release and of the
  CRDs in this tree, and lints the deployments with kube-linter, see
  `.kube-linter.yaml`.
- `make verify-security-model` checks that
  [`security-model.md`](security-model.md) names the security profiles the
  operator applies to its own containers and the API groups of each role in
  `deploy/base/role.yaml`. Update the document together with the RBAC
  markers and the profiles.

The Prow jobs run the scripts of the same name in `hack/`, like
`hack/pull-security-profiles-operator-verify`, which runs `make verify`. A few
checks are not part of it, because they need nix, take long or need tools
which the `Makefile` doesn't download, and run in GitHub Actions only. Run
them when changing what they check:

- `make verify-actions` lints the GitHub workflows with actionlint and
  shellcheck.
- [zizmor](https://docs.zizmor.sh) checks the GitHub workflows for security
  issues like template injection, see the zizmor job of the lint workflow.
- [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2) lints
  the Markdown files with
  [`.markdownlint-cli2.yaml`](../.markdownlint-cli2.yaml), and
  [lychee](https://lychee.cli.rs) checks their links with
  [`lychee.toml`](../lychee.toml), see the docs job of the lint workflow. Pull
  requests only check the links within the repository, including the heading
  fragments, the scheduled run checks the external links too.
- [typos](https://github.com/crate-ci/typos) checks the spelling with
  [`.typos.toml`](../.typos.toml), see the test workflow.
- The helm-chart-lint workflow lints the Helm chart with
  [chart-testing](https://github.com/helm/chart-testing), and the
  `helm-install` job of the test workflow installs it.
- `make verify-bundle` regenerates the OLM bundle, see the OLM workflow.
- `make verify-bpf` rebuilds the BPF objects and `make verify-go-version`
  checks that nix builds with the Go version of `go.mod`, both need nix, see
  the build workflow.
- The CodeQL workflow analyzes the code with the build tags and libraries of
  `make`.
- The image scans, see
  [vulnerability checks and assessments](#vulnerability-checks-and-assessments).
  The e2e tests run in GitHub Actions and Prow, see
  [running e2e tests](#running-e2e-tests).

The [pre-commit hooks](#pre-commit-hooks) run typos and markdownlint as well,
but not lychee and zizmor.

### Pre-commit hooks

[`.pre-commit-config.yaml`](../.pre-commit-config.yaml) has hooks for
[pre-commit](https://pre-commit.com), install them with `pre-commit install`.
They check YAML, JSON, whitespace, typos and Markdown, and run the Makefile
targets of the changed files, like `make verify-shellcheck`,
`make verify-dockerfiles`, `make verify-manifests` and `make verify-actions`,
so that the hooks and the CI use the same pinned linters. `make verify-go-lint`
takes a while and only runs on `git push`. `pre-commit run --all-files` runs
all hooks once.

### Dependencies

[`dependencies.yaml`](../dependencies.yaml) lists the versions which appear in
more than one file, and `make verify-dependencies` checks that they match.
`make verify-dependencies-upstream` checks the entries with an upstream for
newer releases, which the weekly upstream job of the
[dependencies workflow](../.github/workflows/dependencies.yml) runs. It fails
with the available updates, bump them by hand together with the files
`dependencies.yaml` lists.

The Flatcar box of the Flatcar e2e VM, `3510.2.3` in
[`hack/ci/Vagrantfile-flatcar`](../hack/ci/Vagrantfile-flatcar), is pinned on
purpose and has no upstream in `dependencies.yaml`. Newer Flatcar releases
break the e2e job, so don't bump it without fixing the job.

Dependabot only updates the files of its own ecosystem, so it owns the Go
modules, the GitHub actions and the base image digests of the Dockerfiles,
which `dependencies.yaml` does not track. It also bumps the nixpkgs revision
of `flake.lock` once a week, which the images, the BPF objects and `spoc` get
built with. If the new revision changes the compiler of the BPF objects, `make
verify-bpf` fails, so push the result of `make update-bpf` onto its pull
request. If it changes the Go patch release, `make verify-go-version` fails
until the Go version of `go.mod` and the `golang` entries of
`dependencies.yaml` follow.

The generators of committed files have a module of their own,
[`hack/tools/go.mod`](../hack/tools/go.mod), so that neither `go.mod` nor
`vendor/` of the operator carry them. Dependabot ignores them, because their
output changes with their version and `make verify` would fail on its pull
requests. Its entry for `hack/tools` only shapes the security updates of the
module, version updates do not cover its requires, which are all indirect.
Bump the generators by hand in `hack/tools/go.mod` and regenerate the files:

- `sigs.k8s.io/controller-tools` with `make manifests generate deployments
  bundle`.
- `google.golang.org/grpc/cmd/protoc-gen-go-grpc` with `make update-proto`.
- `github.com/maxbrunsfeld/counterfeiter/v6` with `make update-mocks`.

`google.golang.org/protobuf` is not ignored, it is a runtime library and
Dependabot bumps it for security fixes too. Its generator `protoc-gen-go`
stays a tool of `go.mod`, so that it has the version of the runtime library.
That version is in the headers of the generated `api/grpc` files, so push the
result of `make update-proto` onto its pull requests, and onto the ones of
other modules which raise it.

[`.github/dependabot.yml`](../.github/dependabot.yml) ignores a few more
dependencies, with the reason next to each of them:

- `github.com/aquasecurity/libbpfgo`, whose version names the libbpf release
  it is built against, which `dependencies.yaml` tracks, so bump it together
  with libbpf.
- `github.com/google/cel-go`, whose newer releases moved to `cel.dev/cel-go`,
  which Dependabot cannot follow. Switch together with the Kubernetes
  libraries.
- The `crate-ci/typos` action, which `dependencies.yaml` keeps on the release
  of the pre-commit hook, so bump both together by hand.

## Submitting a pull request

Fork the [repository](https://github.com/kubernetes-sigs/security-profiles-operator),
work on a branch of the fork, and run the checks of
[verifying changes](#verifying-changes) and the tests of what you changed. For
changes of the deployment, build an image and test it in a cluster, see
[installing SPO to your cluster from source](#installing-spo-to-your-cluster-from-source).
Then open the pull request with the
[template](../.github/PULL_REQUEST_TEMPLATE.md), which asks for the kind of
the change and a release note, or `NONE` if the change is not user-facing.

## Vulnerability checks and assessments

Two checks keep known vulnerabilities out:

- `make verify-vulnerabilities` runs govulncheck on the source and fails when
  the code calls a vulnerable function that has a fixed version upstream.
- The `ubi-image` job in
  [`.github/workflows/build.yml`](../.github/workflows/build.yml) and the
  `image-scan` jobs in
  [`.github/workflows/test.yml`](../.github/workflows/test.yml) scan the UBI
  image and the images of `Dockerfile` with trivy and fail on every
  vulnerability with an available fix, including the OS packages of the UBI
  image. The trivy scan fails on every vulnerable module in the binaries,
  while govulncheck only fails on the code paths the operator calls, so the
  scan can fail while `make verify` passes. The e2e jobs don't depend on the
  `image-scan` jobs and still run when the scan fails.

Scheduled runs catch new advisories also while no pull request runs, and open
an issue when they fail:

- The build workflow scans the UBI image weekly.
- The [dependencies workflow](../.github/workflows/dependencies.yml) runs
  govulncheck on main and scans the current staging image daily, and scans
  the last released image weekly, since only a new release can fix that one.

Vulnerabilities without a fix are reported but don't fail either check. Both
checks can also fail when a fix gets published for a dependency the operator
already uses, without any change in the pull request. Updating the dependency
to the fixed version resolves that for all pull requests. Dependabot opens
security updates for the advisories of the GitHub advisory database, also for
indirect Go modules, but version updates only for the direct Go modules. The
`golang.org/x` modules often get fixes with an advisory of the Go
vulnerability database only, so an indirect one like `golang.org/x/net` gets
bumped by hand when the daily scan or the scan of a pull request flags it,
like any other indirect module without a security update: `go get
<module>@<fixed version>`, `go mod tidy` and `go mod vendor`.

The UBI image installs the OS package updates of the UBI repositories at build
time. The `ubi-image` job reruns that update whenever the repositories change,
so fixed OS packages need no change in the repository. Local builds reuse the
cached update layer, build without cache to get the latest packages there. If
the scan of the job still fails on an OS package, the vulnerability database
knows of a fix the UBI repositories don't ship yet. Assess it as described
below, or wait for the fixed package. To not block all pull requests while
waiting, add the vulnerability with an expiry date to
[`.trivyignore`](../.trivyignore), which only the image scan reads, and
remove it once the fixed package is available.

When a check fails, update the affected module or image to the fixed version.
Only if the vulnerability doesn't affect the operator, for example because the
vulnerable code is never executed, assess it in the OpenVEX document
[`.openvex.json`](../.openvex.json) in the same pull request:

```shell
vexctl add --in-place .openvex.json \
  --vuln GO-2026-1234 \
  --status not_affected \
  --justification vulnerable_code_not_in_execute_path \
  --impact-statement "Why the code can't be reached, with links to upstream issues." \
  --product pkg:oci/security-profiles-operator,pkg:oci/security-profiles-operator-amd64,pkg:oci/security-profiles-operator-arm64,pkg:oci/security-profiles-operator-ppc64le \
  --subcomponents pkg:golang/example.com/vulnerable/module
```

A statement:

- names the vulnerability as reported by govulncheck or trivy, an alias like
  the CVE works for govulncheck as well
- lists the images as products without version, each with the affected
  package as subcomponent, like the golden templates of
  [`vexctl generate`](https://github.com/openvex/vexctl):
  `pkg:oci/security-profiles-operator` for both checks, the per-arch
  `pkg:oci/security-profiles-operator-{amd64,arm64,ppc64le}` for the staging
  attestations
- has a `status`, and for `not_affected` a
  [justification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)
  plus an `impact_statement` that explains the assessment

`vexctl add` increases the document `version` and sets `last_updated`, do
that by hand when editing the file directly. Remove statements once the
vulnerability is fixed or no longer found.

Neither check fails on `not_affected` or `fixed` statements. Both list the
assessed findings in their output. A `vulnerable_code_not_present` or
`component_not_present` statement is ignored with a warning when govulncheck
observes the vulnerable code again, which needs the symbol table that the
binaries keep because `LDFLAGS` in the [`Makefile`](../Makefile) drops DWARF with
`-w` but not the symbols with `-s`. Without it govulncheck can only report
which vulnerable modules a binary contains, and reports the packages and
symbols of the advisory rather than the ones in the binary. The staging build
also applies the assessments to the VEX documents it attests, see
[staging attestations](release.md#staging-attestations).

## Running unit tests and viewing coverage

SPO uses the Go's `testing` library augmented with [testify](https://github.com/stretchr/testify)
to provide nicer assertions and [counterfeiter](https://github.com/maxbrunsfeld/counterfeiter)
which provides mocks and stubs.

Same as with building SPO, you can use the `*_ENABLED` environment variables to disable
functionality you can't test when running the tests locally:

```shell
BPF_ENABLED=0 APPARMOR_ENABLED=0 make test-unit
```

Running unit tests produces a coverage file under `build/`. To view it
locally in a browser run:

```shell
go tool cover -html=build/coverage.out
```

See the documentation of `go tool cover` for more options like generating
an HTML file or displaying the coverage to stdout.

### Running the unit tests of a package

`make test-unit` runs the tests of all packages. A plain `go test` of a single
package lacks the build tags and the `CGO_LDFLAGS` which the `Makefile`
computes, so the packages which link libbpf, like the BPF recorder and the
enricher, fail to link. `make print-buildtags` and `make print-cgo-ldflags`
print them, with the `*_ENABLED` variables applied:

```shell
CGO_LDFLAGS="$(make -s print-cgo-ldflags)" \
  go test -tags "$(make -s print-buildtags | tr ' ' ',')" ./internal/pkg/daemon/bpfrecorder/...
```

### Integration tests with envtest

The integration tests in [`internal/pkg/integration`](../internal/pkg/integration)
run the controllers of the manager against a real kube-apiserver and etcd from
[envtest](https://book.kubebuilder.io/reference/envtest), without nodes or a
container runtime. They carry the `integration` build tag, so `make test-unit`
leaves them out. Run them with:

```shell
make test-integration
```

The target installs `setup-envtest` into `build/` and downloads the binaries
of the Kubernetes release of the vendored `k8s.io/api` into `build/envtest`.
`ENVTEST_K8S_VERSION` selects another release, for example
`make test-integration ENVTEST_K8S_VERSION=1.36.x`, and
`INTEGRATION_TEST_TIMEOUT` sets the timeout (default `15m`). The CI runs them
in the `integration` job of the build workflow.

A plain `go test -tags integration ./internal/pkg/integration/...` skips the
tests unless `KUBEBUILDER_ASSETS` points to the envtest binaries. The target
fails instead when `setup-envtest` finds none, and sets
`SPO_INTEGRATION_REQUIRED=true`, which makes the tests fail rather than skip
without `KUBEBUILDER_ASSETS`.

### Fuzz tests

The parsers of untrusted input, like the audit log lines, the BPF events, the
pulled profile artifacts, the profiles which get translated into AppArmor
and SELinux policies, the recording annotations and the exec metadata of the
webhook, have fuzz tests. `make test-unit` runs their seed corpus.
`make test-fuzz` fuzzes each target of `FUZZ_TARGETS` for `FUZZ_TIME`
(default `30s`), one after another, because `go test` fuzzes a single target
per run. `FUZZ_TARGETS` defaults to every `func Fuzz` of the test files below
`internal`, `cmd` and `api`:

```shell
make test-fuzz FUZZ_TIME=2m
make test-fuzz FUZZ_TARGETS=./internal/pkg/artifact:FuzzReadProfile
```

A failing input gets written below `testdata/fuzz/<FuzzName>` of the package.
Commit it together with the fix, so that it keeps running as regression test.
The weekly [fuzz workflow](../.github/workflows/fuzz.yml) fuzzes every target
for three minutes and uploads the failing inputs as artifact. New fuzz tests
get picked up without a Makefile change, lower `FUZZ_TIME` of the workflow if
the targets no longer fit into its timeout.

### Mocking interfaces with counterfeiter

In order to test error paths or just code paths that rely on something that's
not available for unit tests (e.g. listing pods), SPO generates mock interfaces
using the [counterfeiter](https://github.com/maxbrunsfeld/counterfeiter)
library. Let's take a look at the `internal/pkg/daemon/enricher` package as
an example of using `counterfeiter`.

The main structure used by the enricher controller is called `Enricher`. Note
that any functionality in that package that we want to mock is provided not
directly, but through an embedded interface called `impl`:

```go
type Enricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	source auditsource.AuditLineSource
	logger logr.Logger
	...
}
```

Both the interface itself and the default implementation (`struct
defaultImpl`) that the package uses normally are located in `impl.go` in the
package directory. The methods of `defaultImpl` are thin wrappers around the
calls into the node or the cluster, the state they need, like the file system
and the logger, is set up by `newDefaultImpl`.

```go
//go:generate go run -modfile=../../../../hack/tools/go.mod -mod=readonly github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	StartTail(src auditsource.AuditLineSource) (chan *types.AuditLine, error)
	ContainerIDForPID(
		cache *ttlcache.Cache[string, string], pid int,
	) (containerID string, started time.Duration, err error)
	PodListerWatcher(c kubernetes.Interface, nodeName string) podindex.ListerWatcher
	...
}

func (d *defaultImpl) ContainerIDForPID(
	cache *ttlcache.Cache[string, string],
	pid int,
) (containerID string, started time.Duration, err error) {
	return util.ContainerIDAndStartTimeForPID(cache, pid)
}
```

The most important part is the `go:generate` and `counterfeiter:generate`
annotations above the interface. These annotations are used by `go generate` to
generate the mocked interfaces, the fake of the enricher is `FakeImpl` of the
`enricherfakes` package. The `-modfile` of `go:generate` runs counterfeiter from
the module of the generators, see [Dependencies](#dependencies). SPO provides a
makefile target `update-mocks` to regenerate the mocked interfaces.

The last step is to actually use the mocked functions in a test. Here is an
example of a test that feeds the audit lines of a channel to the enricher and
makes the `ContainerIDForPID` and `PodListerWatcher` interface methods return
the container and the pod of the lines:

```go
	prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *types.AuditLine) {
		mock.StartTailReturns(lineChan, nil)
		mock.ContainerIDForPIDReturns(containerID, 0, nil)
		mock.PodListerWatcherReturns(podindextest.New(*runningPod()))
	},
```

The test then replaces the implementation of the enricher with the fake
(`sut.impl = mock`), and checks the calls of the enricher with the recording
methods of the fake, like `mock.SendMetricCallCount()` and
`mock.SendMetricArgsForCall(0)`.

## Installing SPO to your cluster from source

The particular steps depend on what features are you interested in testing
(e.g. you can't test SELinux using `kind`) and which Kubernetes distribution
are you running, because different distributions might have different ways
of uploading custom images to the cluster.

On a high level, the process is as follows:

- Build the image with `make image`. You can use a custom `Dockerfile` by
  setting the `DOCKERFILE` variable, e.g. `DOCKERFILE=Dockerfile.ubi make image`,
  and the name of the image with `IMAGE`.
- Make the image available to the cluster. This depends on your cluster type
  and environment and might be one of:
  - copying the container image and loading it on the nodes in single-node
    environments such as those used by CI (see below for an example of the
    Vagrant-based tests)
  - pushing the image to a registry, either external or internal to the cluster
- Install [cert-manager](https://cert-manager.io), see
  [installation](installation.md), and the operator. `make deploy` deploys
  `deploy/operator.yaml` with the image `IMAGE` and a single replica of the
  operator into the cluster of the current `kubectl` context, and applies
  [`examples/config.yaml`](../examples/config.yaml), the default SPOD.

### Distribution specific instructions: OpenShift

Before you start, you must have the `KUBECONFIG` environment variable set
correctly to point to your OpenShift cluster's configuration file, and you need
to be successfully logged in using the `oc login` command.

For convenience, the `Makefile` contains a target called `deploy-openshift-dev` which
deploys SPO in an OpenShift cluster with the appropriate defaults (SELinux is on by default)
and the appropriate settings (no cert-manager needed). It should be noted that `deploy-openshift-dev`
builds the image from `Dockerfile.ubi`, which does not include the eBPF and AppArmor support.

If you modify the code and need to push the images to the cluster again, use the
`push-openshift-dev` Makefile target. Because the targets use the `ImageStream` feature
of OpenShift, simply pushing the new images will trigger a new rollout of the deployments
and DaemonSets. The push targets verify the TLS certificate of the image registry route. If
the cluster serves the route with a self-signed certificate, set `REGISTRY_TLS_VERIFY=false`
to skip the verification with podman, docker reads insecure registries from its daemon
configuration instead.

To build the SPO image with eBPF enabled, use `make image`, which builds the
image with nix and makes it available locally at
`localhost/security-profiles-operator:latest`. Once built, you can deploy this
pre-built image to OpenShift by running `make deploy-prebuilt-openshift-dev`.
Subsequently, if you need to push this locally built image to image registry
used by OpenShift, execute `make push-prebuilt-image-openshift-dev`.

The fastest build-test loop on an OpenShift cluster is to push the SPO images
using `make push-openshift-dev` after each change to the SPO code and then
run the selected [e2e tests](#running-e2e-tests), e.g. to only run SELinux
tests. A set `E2E_SPO_IMAGE` makes the suite skip building and pushing the
image:

```shell
E2E_SPO_IMAGE=image-registry.openshift-image-registry.svc:5000/openshift/security-profiles-operator:latest \
E2E_CLUSTER_TYPE=openshift \
E2E_TEST_SECCOMP=false \
E2E_TEST_BPF_RECORDER=false \
E2E_TEST_LOG_ENRICHER=false \
E2E_TEST_SELINUX=true \
make test-e2e
```

### Tearing down your test environment

There is no teardown target. The profiles use finalizers, which block their
removal once the operator is gone, so remove them before the operator. Follow
[Uninstalling](installation.md#uninstalling), with the manifest you deployed
from, like `deploy/operator.yaml`, or `deploy/openshift-dev.yaml` on OpenShift.

## Running e2e tests

During development, it is often useful to debug the e2e tests or run them
on another distribution than upstream uses in the GitHub CI workflow.

In general, the e2e test run the `test-e2e` `Makefile` target. However,
there is a number of environment variables you might want to fine-tune
to either run only a subset of tests (e.g. only all tests for SELinux,
or conversely do not run any SELinux related tests) or to skip building
and pushing images.

The tests only build with the `e2e` build tag, so that `go test ./...` does
not start them. The `Makefile` targets pass it. The environment variables of
the suite are documented next to their definition in
[suite_test.go](../test/suite_test.go), keep this table in sync with them:

| Variable                    | Default                            | Description                                                                                                                                                                                                                                                                                                                              |
| --------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `E2E_CLUSTER_TYPE`          | `kind`                             | The cluster driver: `kind` creates a kind cluster per test, `vanilla` uses the cluster of the current context, like the Fedora, Flatcar and Ubuntu CI jobs, `openshift` a Red Hat OpenShift cluster.                                                                                                                                     |
| `E2E_SPO_IMAGE`             | per driver                         | The operator image to test. `kind` builds and loads it under this name, unless `E2E_SPO_IMAGE_ARCHIVE` is set, `vanilla` deploys it as is, `openshift` skips building and pushing an image when set.                                                                                                                                     |
| `E2E_SPO_IMAGE_ARCHIVE`     | none                               | `kind` only: an archive of the operator image, like `podman save` writes it, to load instead of building the image. `E2E_SPO_IMAGE` has to name the image in it.                                                                                                                                                                         |
| `E2E_SKIP_BUILD_IMAGES`     | `false`                            | OpenShift only: push the image without building it first.                                                                                                                                                                                                                                                                                |
| `E2E_SELINUXD_IMAGE`        | `RELATED_IMAGE_SELINUXD`           | The selinuxd image to deploy for all node operating systems. `kind` and `vanilla` default to the `RELATED_IMAGE_SELINUXD` image of the operator manifest, `openshift` keeps the images the operator selects per operating system. With `E2E_TEST_SELINUX` on `kind`, it has to be a tagged image, `kind` cannot load one by digest only. |
| `E2E_SPOD_CONFIG`           | none                               | A SPOD manifest which gets applied after deploying the operator, like `test/flatcar-spod-config.yaml`.                                                                                                                                                                                                                                   |
| `E2E_SKIP_FLAKY_TESTS`      | `false`, `true` in `make test-e2e` | Skip the [quarantined test cases](#quarantined-test-cases). `make test-e2e E2E_SKIP_FLAKY_TESTS=false` runs them as well, without retries.                                                                                                                                                                                               |
| `E2E_SKIP_NAMESPACED_TESTS` | `false`                            | Skip the second run of the test cases against the namespaced operator.                                                                                                                                                                                                                                                                   |
| `E2E_TEST_SECCOMP`          | `true`                             | Run the seccomp test cases, which need the kubelet directory at `/var/lib/kubelet`.                                                                                                                                                                                                                                                      |
| `E2E_TEST_SELINUX`          | `false`                            | Run the SELinux test cases, which need a node with SELinux enabled.                                                                                                                                                                                                                                                                      |
| `E2E_TEST_LOG_ENRICHER`     | `false`                            | Run the log enricher test cases, which record profiles from the `audit.log`.                                                                                                                                                                                                                                                             |
| `E2E_TEST_JSON_ENRICHER`    | `false`                            | Run the JSON enricher test cases.                                                                                                                                                                                                                                                                                                        |
| `E2E_TEST_BPF_RECORDER`     | `false`                            | Run the test cases which record through the eBPF recorder.                                                                                                                                                                                                                                                                               |
| `E2E_TEST_BPF_LOG_ENRICHER` | `false`                            | Run the log enricher test case with the BPF source, which only reports AppArmor denials.                                                                                                                                                                                                                                                 |
| `E2E_TEST_WEBHOOK_CONFIG`   | `true`                             | Run the webhook configuration test cases.                                                                                                                                                                                                                                                                                                |
| `E2E_TEST_WEBHOOK_HTTP`     | `true`                             | Run the webhook HTTP version test case.                                                                                                                                                                                                                                                                                                  |
| `E2E_TEST_METRICS_HTTP`     | `true`                             | Run the metrics HTTP version test case.                                                                                                                                                                                                                                                                                                  |
| `E2E_SHARD`                 | none                               | Only run the shard `INDEX/TOTAL` of the test cases, the index starting at 1, see [sharding the test cases](#sharding-the-test-cases).                                                                                                                                                                                                    |
| `E2E_ARTIFACTS_DIR`         | none                               | Write the [diagnostics of failed tests](#failure-diagnostics) to a directory per test below it instead of logging them.                                                                                                                                                                                                                  |
| `CONTAINER_RUNTIME`         | `podman` if found, else `docker`   | The container runtime of the host, detected by the `Makefile`.                                                                                                                                                                                                                                                                           |
| `NODE_ROOTFS_PREFIX`        | none                               | The prefix of the node root filesystem, when commands reach the node through a chroot.                                                                                                                                                                                                                                                   |
| `OPERATOR_MANIFEST`         | `deploy/operator.yaml`             | The cluster wide operator manifest to deploy.                                                                                                                                                                                                                                                                                            |
| `E2E_TEST_BINARY`           | none                               | `Makefile`: a prebuilt test binary (`go test -c -tags e2e ./test`) to run instead of compiling the tests, see the `Makefile`.                                                                                                                                                                                                            |
| `E2E_TEST_SKIP`             | none                               | `Makefile`: a regular expression of the tests to skip, see `-skip` in `go help testflag`.                                                                                                                                                                                                                                                |
| `ARGS`                      | none                               | `Makefile`: additional flags of `make test-e2e` and `make test-spoc-e2e`, like `-run`, see [running a single test case](#running-a-single-test-case).                                                                                                                                                                                   |
| `E2E_RETRY_RUN`             | the quarantined test cases         | `Makefile`: the tests `make test-flaky-e2e` runs with one retry.                                                                                                                                                                                                                                                                         |
| `E2E_RETRY_TIMEOUT`         | `30m`                              | `Makefile`: the timeout of `make test-flaky-e2e`.                                                                                                                                                                                                                                                                                        |
| `E2E_TEST_FLAKY_TESTS_ONLY` | `false`                            | CI scripts in `hack/ci`: run `make test-flaky-e2e` instead of `make test-e2e`.                                                                                                                                                                                                                                                           |
| `E2E_FEDORA_SUITE`          | `enricher`                         | `hack/ci/e2e-fedora.sh`: the test cases of the Fedora job, `enricher` or `selinux`.                                                                                                                                                                                                                                                      |
| `E2E_SPOC_REQUIRE_BPF_LSM`  | `false`                            | `test/spoc`: fail the spoc AppArmor recording tests instead of skipping them without the BPF LSM.                                                                                                                                                                                                                                        |
| `VAGRANT_BUILD_IMAGE`       | `true`                             | `Makefile`: build `image.tar` before booting a test VM if it is missing. CI boots the VMs without it and loads the image later, see `hack/ci/load-vm-image.sh`.                                                                                                                                                                          |

The suite deploys copies of the manifests below `build/e2e-manifests`, the
tracked manifests stay untouched.

### Running a single test case

The test cases are sub tests of the suite method `TestSecurityProfilesOperator`
of `TestSuite`, named after their description, prefixed with `cluster-wide`
or `namespaced` for the run against the cluster wide or the namespaced
operator. `go test` replaces the spaces of the names with underscores. `ARGS`
passes `-run` to `make test-e2e`. A matched test case still gets skipped if
the variable of its feature is off, see the table above. For example, to only
run the seccomp profile recording test cases of the log enricher against the
cluster wide operator:

```shell
make test-e2e \
  E2E_SKIP_NAMESPACED_TESTS=true \
  E2E_TEST_LOG_ENRICHER=true \
  ARGS='-run TestSuite/TestSecurityProfilesOperator/cluster-wide:_Seccomp:_Verify_profile_recording_logs'
```

With a prebuilt `E2E_TEST_BINARY`, `ARGS` are flags of the test binary, like
`-test.run=...`. The quarantined test cases run in the suite method
`TestSecurityProfilesOperator_Flaky` instead. `make test-spoc-e2e` passes
`ARGS` to `go test` the same way.

### Sharding the test cases

The slow CI jobs split the test cases between parallel jobs, each running one
shard of them selected by `E2E_SHARD`, like `E2E_SHARD=2/3`. The quarantined
and the other test cases get split separately, by their duration in CI, which
`testCaseCosts` in [shard_cases_test.go](../test/shard_cases_test.go) lists
together with the switches each test case needs. The test cases which skip
themselves without their switches, or which `E2E_TEST_SKIP` leaves out, count
as nothing. The shards do not depend on `-test.run`, so that the retry of a
failed test case by `make test-flaky-e2e` runs in the shard which failed it.
Every test case runs in exactly one shard, so a cost which is off only makes
the shards less balanced. `TestShardCosts` fails for a test case without a
cost and for a cost of a test case which no longer exists,
`go test -tags e2e -run TestShardCosts ./test` runs it in milliseconds
without a cluster. Update the costs when test cases get much slower or faster.
A shard without test cases skips the suite method, so it neither starts a
cluster nor deploys the operator.

### Quarantined test cases

The test cases are listed in `testCases` in [e2e_test.go](../test/e2e_test.go).
A test case with `flaky: true` is quarantined: `TestSecurityProfilesOperator`
leaves it out and `TestSecurityProfilesOperator_Flaky` runs it instead, where
`make test-flaky-e2e` retries it once when it fails. Its `issue` says why it is
quarantined, ideally with a link to the issue which tracks it.

- `make test-e2e` skips the quarantined test cases, so they never fail the
  CI jobs which run it, including the Prow job. To run them as well, without
  retries, use `make test-e2e E2E_SKIP_FLAKY_TESTS=false`. The suite itself
  only skips them when `E2E_SKIP_FLAKY_TESTS` is set, a plain
  `go test -tags e2e ./test` runs them.
- The Fedora, Flatcar, Ubuntu and kind CI jobs run them in a separate step
  through `make test-flaky-e2e`. That step keeps a JUnit report of all
  attempts, `build/junit-flaky-e2e.xml`, so a test case which only passes on
  retry stays visible. Only the kind job runs the seccomp tests, so it is the
  only one which covers the quarantined seccomp test cases.
- [`test/ci/junit-flakes.py`](../test/ci/junit-flakes.py) takes the reports
  of several runs, oldest first. It fails for test cases which are not
  quarantined but passed only on retry in at least two of the last ten runs,
  and lists the quarantined ones which passed on the first try in the last ten
  runs. `TestSuite` and its methods only fail on their own when their setup
  does, like the one of the cluster, so they are listed apart and do not fail
  the check. To cover all test cases, run the whole suite with retries:
  `make test-flaky-e2e E2E_RETRY_RUN=^TestSuite E2E_RETRY_TIMEOUT=120m`.
  A test case skipped in some environments counts with its outcome in the
  others. `python3 test/ci/junit-flakes.py --self-test` runs the tests of the
  script.
- The nightly [e2e-flakes workflow](../.github/workflows/e2e-flakes.yml) does
  that on kubernix, on kind for the seccomp test cases and in the Fedora VM for
  the SELinux and bpf recorder ones. It runs the script over the reports of
  its last runs, and over the reports of the last runs of the test workflow
  on `main`, which cover the quarantined test cases on all e2e environments.
  It downloads the reports of 15 runs, so that a run without reports, like a
  cancelled one, does not keep a test case from getting promoted. A run which
  failed partway and uploaded a partial report counts, and a test case missing
  from it did not pass in that run. It fails when a test case needs to be
  quarantined and lists the ones to promote in the job summary. A failed
  scheduled run opens an issue, or comments on the open one.

To quarantine a flaky test case, set `flaky: true` and its `issue`. To promote
it, remove both again. New test cases start quarantined with
`issue: newTestCaseIssue` until they pass reliably in CI, and need an entry in
`testCaseCosts`, see [sharding the test cases](#sharding-the-test-cases).

### Failure diagnostics

When a test or sub test fails, or the test binary is about to time out, the
suite collects the pods, events and the SPOD, the webhook
configurations, the profiles, the logs of the operator pods and the journals
of the container runtime and the kubelet of each node. They get logged, or
written to a directory per test below `E2E_ARTIFACTS_DIR` if it is set, which
the CI jobs upload when they fail.

### Running the Ubuntu e2e tests on kubernix

The Ubuntu based e2e tests and the seccomp base profile recording run on a
[kubernix](https://github.com/saschagrunert/kubernix) cluster directly on the
GitHub Actions runner, which is the only node of the cluster. The same works
on a Linux machine with [Nix](https://nixos.org/download) installed, but only
use a disposable one: `hack/ci/start-kubernix.sh` runs the cluster as root and
changes the host, for example its hostname and DNS resolver.

```shell
make image
podman save -o image.tar security-profiles-operator
hack/ci/start-kubernix.sh image.tar
export SPO_KUBELET_DIR=/var/lib/kubernix/kubelet/kubernix/run
hack/ci/e2e-ubuntu.sh
```

`hack/ci/e2e-ubuntu.sh` sets the kubelet directory of kubernix in
`deploy/operator.yaml` and `deploy/namespace-operator.yaml`, restore them with
`git checkout deploy` afterwards. The logs of the cluster components are below
`/var/lib/kubernix`.

### Running the Fedora e2e tests on a local VM

Some e2e tests, especially the SELinux based ones require a VM, because the
tests need a kernel with SELinux support. This section shows how to run the
Fedora based e2e tests locally and how to debug SPO at the same time. It
needs [Vagrant](https://developer.hashicorp.com/vagrant/install) and follows
the `e2e-fedora` jobs of the
[test workflow](../.github/workflows/test.yml) in greater detail.

The Vagrant based tests only build the SPO image if the file `image.tar` does
not exist, so remove it after changing the SPO code. The tests run on the VM
itself from within the `/vagrant` directory, so changing the test sources on
your machine while the VM is up has no effect. Either sync the files to the
VM, edit the files on the VM or provision it again. A `build/e2e.test` left
over from CI or an earlier run is a prebuilt test binary, which
`hack/ci/e2e-fedora.sh` runs instead of compiling the tests, so remove it as
well after changing the tests.

First, set up the VM, making sure the image gets rebuilt:

```shell
rm -f image.tar build/e2e.test
make vagrant-up-fedora
```

This will run for a fair bit and provision a new single-node cluster running
Fedora and load the `image.tar` that contains the SPO image to the local
container storage. Next, export the `RUN` environment variable and try
interacting with the cluster:

```shell
export RUN=./hack/ci/run-fedora.sh
$RUN kubectl get pods -A
```

`hack/ci/e2e-fedora.sh` runs one of the two suites of the Fedora CI jobs,
selected by `E2E_FEDORA_SUITE`. The default `enricher` suite runs the log and
JSON enricher test cases, the `selinux` suite the SELinux, bpf recorder and
profile merging test cases, on an SELinux enforcing node:

```shell
$RUN hack/ci/e2e-fedora.sh
$RUN E2E_FEDORA_SUITE=selinux hack/ci/e2e-fedora.sh
```

`$RUN` runs any command on the VM, as root and in `/vagrant`, so the variables
of the [table above](#running-e2e-tests) can be set the same way, for example
`E2E_TEST_FLAKY_TESTS_ONLY=true` to only run the quarantined test cases. Or
`vagrant ssh` into the machine and run commands and edit files there. For
example, to get the SPO logs:

```shell
$RUN kubectl logs deploy/security-profiles-operator -nsecurity-profiles-operator
```

### The Debian and Flatcar VMs

The Debian and Flatcar CI jobs use VMs in the same way: `make vagrant-up-debian`
and `make vagrant-up-flatcar` boot them, and `hack/ci/run-debian.sh` and
`hack/ci/run-flatcar.sh` are their `RUN` prefixes. The Debian VM runs the
`spoc` and AppArmor tests, `hack/ci/e2e-spoc.sh` and `hack/ci/e2e-apparmor.sh`,
the Flatcar VM runs `hack/ci/e2e-flatcar-dev-container.sh`. The Flatcar box
is pinned on purpose, see [dependencies](#dependencies).

### Running the spoc e2e tests

`make test-spoc-e2e` builds `spoc` and runs its end-to-end tests in
[`test/spoc`](../test/spoc), which record and run profiles on the local host
without a cluster. Like the e2e suite, they only build with the `e2e` build
tag. The CI runs them on the Debian VM and on an arm64 runner
through `hack/ci/e2e-spoc.sh`.

## Adding support for a new cluster type

The e2e tests support the cluster types `kind`, `vanilla` and `openshift` of
`E2E_CLUSTER_TYPE`, see [running e2e tests](#running-e2e-tests). To add a new
one, on a high level, this needs to be done:

- Create a structure representing the new cluster type. This structure must
  at minimum embed the `e2e` structure plus any additional cluster specific
  state. The `e2e` structure itself embeds the `Suite` structure from
  `testify` which provides setup and teardown methods and some functions e.g.
  for executing a command on the nodes or waiting that the cluster is ready.
  As an example, OpenShift uses the `oc debug` command to execute commands on
  nodes and doesn't wait for the cluster being ready at all, but instead lets
  the user of the test suite to provision the cluster. In comparison, the
  `kind` test driver uses `docker` to execute commands on "nodes" and waits
  for all pods in all namespaces before running the tests.
  Set `nodeCommand` next to `execNode`. It runs the command with its
  arguments unchanged on the node and returns the output without printing
  it or failing the test. The failure diagnostics use it to collect the node
  journals. Set `readNodeLogFiles` as well if it can read the container log
  files of the kubelet as root and quickly: the enricher and BPF recorder
  tests then read the lines of the daemon containers which the kubelet
  rotated, which `kubectl logs` misses.
- Instantiate the structure in the switch-case statement in `TestSuite`.

## Building the operator image with support for AppArmor

The AppArmor functionality is conditionally built based on the `apparmor`
build tag. Local builds with `make` enable it by default, set
`APPARMOR_ENABLED=0` to disable it. The image built by `make image` always
includes the AppArmor support, see [Building SPO locally](#building-spo-locally).

A full process of building the image, pushing it to a registry and deploying
it into a cluster with [cert-manager](https://cert-manager.io), with
`podman`, or `docker` if that is the `CONTAINER_RUNTIME`:

```shell
export IMAGE=<registry-and-image-name>:<label>

make image
podman push "${IMAGE}"

make deploy

kubectl -n security-profiles-operator patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'

kubectl apply -f examples/apparmorprofile.yaml
kubectl apply -f examples/pod-apparmor.yaml
```
