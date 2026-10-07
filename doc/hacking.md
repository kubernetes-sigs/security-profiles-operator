# Developing SPO
This document describes how to build, install and test SPO for development
purposes. It is not exhaustive - knowledge of how an operator works is
presumed and PRs are always welcome.

<!-- toc -->
- [Building SPO locally](#building-spo-locally)
  - [Other build targets](#other-build-targets)
- [Verifying changes](#verifying-changes)
  - [Pre-commit hooks](#pre-commit-hooks)
- [Submitting a Pull Request (PR)](#submitting-a-pull-request-pr)
- [Vulnerability checks and assessments](#vulnerability-checks-and-assessments)
- [Running unit tests and viewing coverage](#running-unit-tests-and-viewing-coverage)
  - [Integration tests with envtest](#integration-tests-with-envtest)
  - [Fuzz tests](#fuzz-tests)
  - [Mocking interfaces with counterfeiter](#mocking-interfaces-with-counterfeiter)
- [Installing SPO to your cluster from source](#installing-spo-to-your-cluster-from-source)
  - [Distribution specific instructions: OpenShift](#distribution-specific-instructions-openshift)
  - [Tearing down your test environment](#tearing-down-your-test-environment)
- [Running e2e tests](#running-e2e-tests)
  - [Quarantined test cases](#quarantined-test-cases)
  - [Failure diagnostics](#failure-diagnostics)
  - [Running the Ubuntu e2e tests on kubernix](#running-the-ubuntu-e2e-tests-on-kubernix)
  - [Running the Fedora e2e tests on a local VM](#running-the-fedora-e2e-tests-on-a-local-vm)
  - [Running the spoc e2e tests](#running-the-spoc-e2e-tests)
- [Adding support for a new distribution](#adding-support-for-a-new-distribution)
- [Building the operator image with support for AppArmor](#building-the-operator-image-with-support-for-apparmor)
<!-- /toc -->

## Building SPO locally
Even though SPO is a Kubernetes operator and as such is normally not meant to
be used locally, but rather deployed in a cluster from pre-built images,
it's often useful to be able to run a quick build or a test on your local machine.

Depending on what OS and version you are developing on and what features you
want to build with, you might need to either install extra dependencies or
disable features that would require them.

There are currently two optional features at build time
- eBPF based recording
  - This feature requires a rather new `libbpf` which requires a new `libelf`
    version which in turn requires a new `libz` version.
    - Install the necessary libraries based on your build OS.
      For example, on Fedora, you'll need to install the RPMs `elfutils-libelf-devel` and `libbpf-devel`
  - disable with `BPF_ENABLED=0`
- AppArmor
  - This feature requires apparmor headers and development libraries as well as the `go-apparmor` bindings
  - disable with `APPARMOR_ENABLED=0`

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

Also make sure you have `clang-tools-extra` installed

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

- `make nix` builds the binaries for all architectures with
  [Nix](https://nixos.org/download) into `build.tar.gz`, `make nix-amd64`,
  `make nix-arm64` and so on build a single architecture. `make nix-spoc` and
  `make nix-spoc-<arch>` build `spoc` the same way. Nix needs no
  native libraries on the host, and `make update-nixpkgs` updates its pinned
  package set.
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
  deployment, the Helm values and `dependencies.yaml`. Run
  `make deployments bundle` afterwards to regenerate the manifests.
  `hack/update-selinuxd.sh --check` only reports moved tags, which the weekly
  dependencies workflow does.
- `make update-docs` regenerates the command line reference of `spoc` and the
  operator binary below [`reference/`](reference/) after changing their flags,
  `make verify-docs` checks that it is up to date.
- `make update-toc` updates the table of contents of every document with a
  `<!-- toc -->` marker after changing its headings, `make verify-toc` checks
  that they are up to date.

`nix develop` opens a shell with the Go toolchain, the C libraries of the
build and the tools of the Makefile targets (clang and llvm for the BPF
programs, protobuf, shellcheck, helm, kind, kubectl, jq and yq), so the build
with all features works without installing anything on the host. The
repository also has a [development
container](../.devcontainer/devcontainer.json) with Go and Nix, for editors
which support it. Without the native libraries listed above, use the Nix
targets or disable the optional features.

## Verifying changes

`make verify` runs all checks which need no cluster, each of which is a target
of its own. The linters get downloaded into `build/` with pinned versions and
checksums, so no local installation is needed. Besides the checks of the
code, the generated files and the dependencies, these are:

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
checks are not part of it, because they need nix or take long, and run in
GitHub Actions only. Run them when changing what they check:

- `make verify-actions` lints the GitHub workflows with actionlint and
  shellcheck, see the lint workflow.
- `make verify-bundle` regenerates the OLM bundle, see the OLM workflow.
- `make verify-bpf` rebuilds the BPF objects and `make verify-go-version`
  checks that nix builds with the Go version of `go.mod`, both need nix, see
  the build workflow.

### Pre-commit hooks

[`.pre-commit-config.yaml`](../.pre-commit-config.yaml) has hooks for
[pre-commit](https://pre-commit.com), install them with `pre-commit install`.
They check YAML, JSON, whitespace, typos and Markdown, and run the Makefile
targets of the changed files, like `make verify-shellcheck`,
`make verify-dockerfiles`, `make verify-manifests` and `make verify-actions`,
so that the hooks and the CI use the same pinned linters. `make verify-go-lint`
takes a while and only runs on `git push`. `pre-commit run --all-files` runs
all hooks once.

## Submitting a Pull Request (PR)

Here's the process for contributing your changes:

1.  **Fork and Branch:**
    * First, create your own copy (a "fork") of the [main repository](https://github.com/kubernetes-sigs/security-profiles-operator) on GitHub.
    * Then, create a new branch within your forked repository to work on your changes.

2.  **Build and Test:**
    * Build a container image of your changes. This ensures your code runs in a kubernetes environment (Ex: OpenShift).

3.  **Verify:**
    * Run the command `make verify`. This command executes automated checks (like code style) to ensure your changes meet the project's standards. Make sure this command passes without any errors. The CI also runs `make verify-bpf`, which rebuilds the committed BPF objects, and `make verify-bundle`, which regenerates the OLM bundle. Both are not part of `make verify`, run them when changing the BPF programs or the deployment manifests.
    * If a vulnerability check fails, see [vulnerability checks and assessments](#vulnerability-checks-and-assessments).

4.  **PR Description:**
    * When you create your Pull Request to merge your changes back into the main repository, please provide a clear description.
    * Specifically, make sure to clearly indicate:
        * **Type of PR:** What kind of change is this?
        * **User-facing change:** If your changes will be noticeable to users of the project, briefly explain what those changes are. If not, you must state "NONE"

## Vulnerability checks and assessments

Two checks keep known vulnerabilities out:

- `make verify-vulnerabilities` runs govulncheck on the source and fails when
  the code calls a vulnerable function that has a fixed version upstream.
- The `operator-image` and `ubi-image` jobs in
  [`.github/workflows/build.yml`](../.github/workflows/build.yml) scan the built
  images with trivy and fail on every vulnerability with an available fix,
  including the OS packages of the UBI image.

Vulnerabilities without a fix are reported but don't fail either check. Both
checks can also fail when a fix gets published for a dependency the operator
already uses, without any change in the pull request. Updating the dependency,
usually through a Dependabot pull request, resolves that for all pull requests.

When a check fails, update the affected module or image to the fixed version.
Only if the vulnerability doesn't affect the operator, for example because the
vulnerable code is never executed, assess it in the OpenVEX document
[`.openvex.json`](../.openvex.json) in the same pull request:

```console
> vexctl add --in-place .openvex.json \
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
directly, but through implementing an interface called `impl`:
```go
type Enricher struct {
	apienricher.UnimplementedEnricherServer
	impl
	logger           logr.Logger
    ...
}
```
Both the interface itself and the default implementation (`struct
defaultImpl`) that the package uses normally is located in `impl.go`
in the package directory. Note that the structure `defaultImpl` has no
members (no state) and all parameters are provided to the methods.

```go
type defaultImpl struct{}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	ListPods(ctx context.Context, c kubernetes.Interface, nodeName string) (*v1.PodList, error)
    ...
}

func (d *defaultImpl) ListPods(
	ctx context.Context, c kubernetes.Interface, nodeName string,
) (*v1.PodList, error) {
	return c.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + nodeName,
	})
}
```

The most important part is the `go:generate` and `counterfeiter:generate`
annotations above the interface. These annotations are used by `go generate` to
generate the mocked interfaces. SPO provides a makefile target `update-mocks`
to regenerate the mocked interfaces.

The last step is to actually use the mocked functions in a test. Here is an example of a
test that makes the `ListPods` interface method to return provided pods:
```go
	prepare: func(mock *enricherfakes.FakeImpl, lineChan chan *tail.Line) {
		mock.GetenvReturns(node)
		mock.LinesReturns(lineChan)
		mock.ContainerIDForPIDReturns(containerID, nil)
		mock.ListPodsReturns(&v1.PodList{Items: []v1.Pod{{
			ObjectMeta: metav1.ObjectMeta{
				Name:      pod,
				Namespace: namespace,
			},
			Status: v1.PodStatus{
				ContainerStatuses: []v1.ContainerStatus{{
					ContainerID: crioPrefix + containerID,
				}},
			},
		}}}, nil)
	},
```

## Installing SPO to your cluster from source
The particular steps depend on what features are you interested in testing
(e.g. you can't test SELinux using `kind`) and which Kubernetes distribution
are you running, because different distributions might have different ways
of uploading custom images to the cluster.

On a high level, the process is as follows:
  - build the images with `make image`
    - note that you can use a custom `Dockerfile` by setting the `DOCKERFILE`
      variable, e.g. `DOCKERFILE=Dockerfile.ubi make image`
  - make the images available to the cluster. This depends on your cluster
    type and environment and might be one of:
    - copying the container images and loading them on the nodes in
      single-cluster environments such as those used by CI (see below for an example
      of the Vagrant-based tests)
    - pushing the images to a registry, either external or internal to the cluster
    - ..or anything else, really
  - install the operator using the manifests under `deploy/`, make sure
    to change the image references to point to your images

### Distribution specific instructions: OpenShift
Before you start, you must have the `KUBECONFIG` environment variable set correctly to point to your 
OpenShift cluster's configuration file, and you need to be successfully logged in using the `oc login` command.

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

To build the SPO image with eBPF enabled, use `make image`, which builds the image with nix and
makes it available locally at `localhost/security-profiles-operator:latest`. Once built, you can deploy this pre-built 
image to OpenShift by running `make deploy-prebuilt-openshift-dev`. Subsequently, if you need to push this locally 
built image to image registry used by OpenShift, execute `make push-prebuilt-image-openshift-dev`.

The fastest build-test loop on an OpenShift cluster is to push the SPO images
using `make push-openshift-dev` after each change to the SPO code and then
run the selected [e2e tests](#running-e2e-tests), e.g. to only run SELinux tests:
```shell
E2E_SPO_IMAGE=image-registry.openshift-image-registry.svc:5000/openshift/security-profiles-operator:latest \
E2E_CLUSTER_TYPE=openshift \
E2E_SKIP_BUILD_IMAGES=true \
E2E_TEST_SECCOMP=false \
E2E_TEST_BPF_RECORDER=false \
E2E_TEST_LOG_ENRICHER=false \
E2E_TEST_SELINUX=true \
make test-e2e
```

### Tearing down your test environment
There is no teardown target. The profiles use finalizers, which block their
removal once the operator is gone, so remove them before the operator. Follow
[Uninstalling](troubleshooting.md#uninstalling), with the manifest you deployed
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

| Variable                    | Default                                       | Description                                                                                                                                                                                          |
| --------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `E2E_CLUSTER_TYPE`          | `kind`                                        | The cluster driver: `kind` creates a kind cluster per test, `vanilla` uses the cluster of the current context, like the Fedora, Flatcar and Ubuntu CI jobs, `openshift` a Red Hat OpenShift cluster. |
| `E2E_SPO_IMAGE`             | per driver                                    | The operator image to test. `kind` builds and loads it under this name, `vanilla` deploys it as is, `openshift` skips pushing an image when set.                                                     |
| `E2E_SKIP_BUILD_IMAGES`     | `false`                                       | OpenShift only: push the image without building it first.                                                                                                                                            |
| `E2E_SELINUXD_IMAGE`        | `quay.io/security-profiles-operator/selinuxd` | The selinuxd image to deploy.                                                                                                                                                                        |
| `E2E_SPOD_CONFIG`           | none                                          | A SPOD manifest which gets applied after deploying the operator, like `test/flatcar-spod-config.yaml`.                                                                                               |
| `E2E_SKIP_FLAKY_TESTS`      | `false`, `true` in `make test-e2e`            | Skip the [quarantined test cases](#quarantined-test-cases). `make test-e2e E2E_SKIP_FLAKY_TESTS=false` runs them as well, without retries.                                                           |
| `E2E_SKIP_NAMESPACED_TESTS` | `false`                                       | Skip the second run of the test cases against the namespaced operator.                                                                                                                               |
| `E2E_TEST_SECCOMP`          | `true`                                        | Run the seccomp test cases, which need the kubelet directory at `/var/lib/kubelet`.                                                                                                                  |
| `E2E_TEST_SELINUX`          | `false`                                       | Run the SELinux test cases, which need a node with SELinux enabled.                                                                                                                                  |
| `E2E_TEST_LOG_ENRICHER`     | `false`                                       | Run the log enricher test cases, which record profiles from the `audit.log`.                                                                                                                         |
| `E2E_TEST_JSON_ENRICHER`    | `false`                                       | Run the JSON enricher test cases.                                                                                                                                                                    |
| `E2E_TEST_BPF_RECORDER`     | `false`                                       | Run the test cases which record through the eBPF recorder.                                                                                                                                           |
| `E2E_TEST_BPF_LOG_ENRICHER` | `false`                                       | Run the log enricher test case with the BPF source, which only reports AppArmor denials.                                                                                                             |
| `E2E_TEST_WEBHOOK_CONFIG`   | `true`                                        | Run the webhook configuration test cases.                                                                                                                                                            |
| `E2E_TEST_WEBHOOK_HTTP`     | `true`                                        | Run the webhook HTTP version test case.                                                                                                                                                              |
| `E2E_TEST_METRICS_HTTP`     | `true`                                        | Run the metrics HTTP version test case.                                                                                                                                                              |
| `E2E_ARTIFACTS_DIR`         | none                                          | Write the [diagnostics of failed tests](#failure-diagnostics) to a directory per test below it instead of logging them.                                                                              |
| `CONTAINER_RUNTIME`         | `podman` if found, else `docker`              | The container runtime of the host, detected by the `Makefile`.                                                                                                                                       |
| `NODE_ROOTFS_PREFIX`        | none                                          | The prefix of the node root filesystem, when commands reach the node through a chroot.                                                                                                               |
| `OPERATOR_MANIFEST`         | `deploy/operator.yaml`                        | The cluster wide operator manifest to deploy.                                                                                                                                                        |
| `E2E_TEST_BINARY`           | none                                          | `Makefile`: a prebuilt test binary (`go test -c -tags e2e ./test`) to run instead of compiling the tests, see the `Makefile`.                                                                        |
| `E2E_TEST_SKIP`             | none                                          | `Makefile`: a regular expression of the tests to skip, see `-skip` in `go help testflag`.                                                                                                            |
| `E2E_RETRY_RUN`             | the quarantined test cases                    | `Makefile`: the tests `make test-flaky-e2e` runs with one retry.                                                                                                                                     |
| `E2E_RETRY_TIMEOUT`         | `30m`                                         | `Makefile`: the timeout of `make test-flaky-e2e`.                                                                                                                                                    |
| `E2E_TEST_FLAKY_TESTS_ONLY` | `false`                                       | CI scripts in `hack/ci`: run `make test-flaky-e2e` instead of `make test-e2e`.                                                                                                                       |
| `E2E_FEDORA_SUITE`          | `enricher`                                    | `hack/ci/e2e-fedora.sh`: the test cases of the Fedora job, `enricher` or `selinux`.                                                                                                                  |

The suite deploys copies of the manifests below `build/e2e-manifests`, the
tracked manifests stay untouched.

### Quarantined test cases

The test cases are listed in `testCases` in [e2e_test.go](../test/e2e_test.go).
A test case with `flaky: true` is quarantined: `TestSecurityProfilesOperator`
leaves it out and `TestSecurityProfilesOperator_Flaky` runs it instead, where
`make test-flaky-e2e` retries it once when it fails. Its `issue` says why it is
quarantined, ideally with a link to the issue which tracks it.

- `make test-e2e` skips the quarantined test cases, so they never fail the
  CI jobs which run it, including the Prow job and `e2e-kind`. To run them
  as well, without retries, use `make test-e2e E2E_SKIP_FLAKY_TESTS=false`.
  The suite itself only skips them when `E2E_SKIP_FLAKY_TESTS` is set, a
  plain `go test -tags e2e ./test` runs them.
- The Fedora, Flatcar and Ubuntu CI jobs run them in a separate step through
  `make test-flaky-e2e`. That step keeps a JUnit report of all attempts,
  `build/junit-flaky-e2e.xml`, so a test case which only passes on retry
  stays visible.
- [`test/ci/junit-flakes.py`](../test/ci/junit-flakes.py) takes the reports
  of several runs, oldest first. It fails for test cases which are not
  quarantined but passed only on retry in the last three runs, and lists the
  quarantined ones which passed on the first try in the last five runs. To
  cover all test cases, run the whole suite with retries:
  `make test-flaky-e2e E2E_RETRY_RUN=^TestSuite E2E_RETRY_TIMEOUT=120m`.
  A test case skipped in some environments counts with its outcome in the
  others. `python3 test/ci/junit-flakes.py --self-test` runs the tests of the
  script.
- The nightly [e2e-flakes workflow](../.github/workflows/e2e-flakes.yml) does
  that on kubernix and runs the script over the reports of its last runs, and
  over the reports of the last runs of the test workflow on `main`, which
  cover the quarantined test cases on all e2e environments. It fails when a
  test case needs to be quarantined and lists the ones to promote in the job
  summary.

To quarantine a flaky test case, set `flaky: true` and its `issue`. To promote
it, remove both again. New test cases start quarantined until they pass
reliably in CI.

### Failure diagnostics

When a test or sub test fails, or the test binary is about to time out, the
suite collects the pods, events and the `spod` resource, the webhook
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

```console
> make image
> podman save -o image.tar security-profiles-operator
> hack/ci/start-kubernix.sh image.tar
> export SPO_KUBELET_DIR=/var/lib/kubernix/kubelet/kubernix/run
> hack/ci/e2e-ubuntu.sh
```

`hack/ci/e2e-ubuntu.sh` sets the kubelet directory of kubernix in
`deploy/operator.yaml` and `deploy/namespace-operator.yaml`, restore them with
`git checkout deploy` afterwards. The logs of the cluster components are below
`/var/lib/kubernix`.

### Running the Fedora e2e tests on a local VM
Some e2e tests, especially the SELinux based ones require a VM,
because the tests need a kernel with SELinux support. Let's show how
to run the Fedora-based e2e tests locally and how to debug SPO at
the same time. Having [vagrant](https://www.vagrantup.com/downloads)
installed is a prerequisite. This section more-or-less follows the [github CI
workflow](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/.github/workflows/test.yml),
just in greater detail.

Note that the vagrant based tests only rebuild the SPO image if the file
`image.tar` does not exist.  When changing the SPO code, make sure to remove
the file manually. Also note that the tests themselves are executed on the
vagrant machine itself from within the `/vagrant` directory, so changing
the test source files on your machine while the machine is up won't have
any effect. Either rsync the files to the vagrant machine, edit the files
on the VM or simply re-provision it.

First, let's set up the vagrant machine, making sure the image will be rebuilt:
```shell
rm -f image.tar
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

To run all the tests, execute:
```shell
$RUN hack/ci/e2e-fedora.sh
```
As said above, the `$RUN` commands are executed on the VM itself, so in order
to change what tests are executed change the `e2e-fedora.sh` file on the VM:
```shell
vagrant ssh
vi /vagrant/hack/ci/e2e-fedora.sh
```
Or just `vagrant ssh` into the machine and run commands and edit files
there. You can also use the `RUN` prefix to run any commands, e.g. to get
the SPO logs:
```shell
$RUN kubectl logs deploy/security-profiles-operator -nsecurity-profiles-operator
```

The Debian and Flatcar CI jobs use VMs in the same way: `make vagrant-up-debian`
and `make vagrant-up-flatcar` boot them, and `hack/ci/run-debian.sh` and
`hack/ci/run-flatcar.sh` are their `RUN` prefixes. The Debian VM runs the
`spoc` and AppArmor tests, `hack/ci/e2e-spoc.sh` and `hack/ci/e2e-apparmor.sh`,
the Flatcar VM runs `hack/ci/e2e-flatcar-dev-container.sh`.

### Running the spoc e2e tests
`make test-spoc-e2e` builds `spoc` and runs its end-to-end tests in
[`test/spoc`](../test/spoc), which record and run profiles on the local host
without a cluster. The CI runs them on the Debian VM and on an arm64 runner
through `hack/ci/e2e-spoc.sh`.

## Adding support for a new distribution
As noted above, three different distributions are supported in our e2e tests
at the time of the writing. To add a new distribution to the e2e tests,
on a high level, this needs to be done:
 - Create a structure representing the new distribution. This structure must
   at minimum embed the `e2e` structure plus any additional distribution
   specific state. The `e2e` structure itself embeds the `Suite` structure
   from `testify` which provides setup and teardown methods and some functions
   e.g. for executing a command on the nodes or waiting that the cluster is
   ready. As an example, OpenShift uses the `oc debug` command to execute
   commands on nodes and doesn't wait for the cluster being ready at all,
   but instead lets the user of the test suite to provision the cluster. In
   comparison, the `kind` test driver uses `docker` to execute commands on
   "nodes" and waits for all pods in all namespaces before running the tests.
   Set `nodeCommand` next to `execNode`, the failure diagnostics use it to
   collect the node journals without failing the test.
 - Instantiate the structure in the switch-case statement in `TestSuite`.

## Building the operator image with support for AppArmor

The AppArmor functionality is conditionally built based on the `apparmor`
build tag. Local builds with `make` enable it by default, set
`APPARMOR_ENABLED=0` to disable it. The image built by `make image` always
includes the AppArmor support, see [Building SPO locally](#building-spo-locally).

A full process of building, pushing it to a registry and deploying it into a cluster:

```sh
export IMAGE=<registry-and-image-name>:<label>

make image
docker push "${IMAGE}"

make deploy

SPO_NS=security-profiles-operator
kubectl -n $SPO_NS patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'

kubectl -n $SPO_NS patch deploy security-profiles-operator --type=merge -p '{"spec": {"template": {"spec": {"containers": [{"name":"security-profiles-operator", "image": "'$IMAGE'"}]}}}}'

kubectl apply -f examples/apparmorprofile.yaml
kubectl apply -f examples/pod-apparmor.yaml
```
