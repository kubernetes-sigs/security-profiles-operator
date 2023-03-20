# Developing SPO
This document describes how to build, install and test SPO for development
purposes. It is not exhaustive - knowledge of how an operator works is
presumed and PRs are always welcome.

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

To build SPO with all the features simply run:
```shell
make
```
To disable features, prefix `make` with environment variables that deselect them:
```shell
BPF_ENABLED=0 APPARMOR_ENABLED=0 make
```

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
	impl             impl
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
	ListPods(c *kubernetes.Clientset, nodeName string) (*v1.PodList, error)
    ...
}

func (d *defaultImpl) ListPods(
	c *kubernetes.Clientset, nodeName string,
) (*v1.PodList, error) {
	return c.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
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
For convenience, the `Makefile` contains a target called `deploy-openshift-dev` which
deploys SPO in an OpenShift cluster with the appropriate defaults (SELinux is on by default)
and the appropriate settings (no cert-manager needed).

If you modify the code and need to push the images to the cluster again, use the
`push-openshift-dev` Makefile target. Because the targets use the `ImageStream` feature
of OpenShift, simply pushing the new images will trigger a new rollout of the deployments
and DaemonSets.

### Tearing down your test environment
At the moment, there's no teardown target provided. At the same time, some
custom resources, notably the policies themselves use finalizers which prevent
them from being removed if the operator itself is not running anymore. The
best way to remove the operator is to remove the policies first, followed
by removing the deployment:
```shell
kubectl delete sp --all
kubectl delete selinuxprofiles --all
kubectl delete -f deploy/operator.yaml  
```

On OpenShift, delete the OpenShift specific manifest instead after deleting
the policies:
```shell
oc delete sp --all
oc delete selinuxprofiles --all
oc delete -f deploy/openshift-dev.yaml
```

## Running e2e tests
During development, it is often useful to debug the e2e tests or run them
on another distribution than upstream uses in the GitHub CI workflow.

In general, the e2e test run the `test-e2e` `Makefile` target. However,
there is a number of environment variables you might want to fine-tune
to either run only a subset of tests (e.g. only all tests for SELinux,
or conversely do not run any SELinux related tests) or to skip building
and pushing images.

The following environment variables are currently
available. For a full and up-to-date overview, see the
[suite_test.go](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/test/suite_test.go)
source file:

- `E2E_CLUSTER_TYPE` - The type of the cluster you are testing against. The
   currently supported types are:
  - `kind` - Run tests against a [kind](https://kind.sigs.k8s.io/)
     cluster. This is the default as well as used for the
    `pull-security-profiles-operator-test-e2e` prow target in GitHub.
  - `vanilla` - Run tests against a vanilla kubernetes cluster. This is
     used in GitHub Actions CI for Fedora and Ubuntu based e2e tests.
  - `openshift` - Red Hat OpenShift.
- `E2E_SKIP_BUILD_IMAGES` - Currently used by OpenShift tests only. By
   default, images are rebuilt before being pushed to the repository.
   Setting this variable to `false` disables building the images, which
   results in faster test iteration.
- `E2E_SPO_IMAGE` - Set to test a custom image. Depending on the value of
   `E2E_CLUSTER_TYPE`, this variable triggers different behavior:
  - `kind`: since `kind` always uses local images that are always built and
    pushed, just affects the tag of the images
  - `vanilla`: really just sets the images to test
  - `openshift`: if set, skip pushing images to cluster. Typically, you'd set the value to
    `image-registry.openshift-image-registry.svc:5000/openshift/security-profiles-operator:latest` to make sure all
    tests keep reusing the same image when iterating on test code.
- `CONTAINER_RUNTIME` - `Makefile` tries to detect if `podman` if `podman`
   is found in `PATH`, otherwise defaults to `docker`. Set to a different
   value in case you want to use a totally different container runtime.
- `E2E_TEST_SELINUX` - Whether to run SELinux related tests. This is set to
   true by default for Fedora based CI, otherwise false.
- `E2E_TEST_LOG_ENRICHER` - Whether to run log enricher e2e tests, which
   record seccomp or SELinux profiles by tailing the `audit.log`.
- `E2E_TEST_SECCOMP` - Whether to run seccomp related e2e tests. Our CI
   tests the seccomp tests in the kind-based prow target only.
- `E2E_TEST_BPF_RECORDER` - Whether to test recording of seccomp profiles
   using our eBPF recorder. Currently, enabled for Fedora only.

### Running the Fedora or Ubuntu e2e tests on a local VM
Some e2e tests, especially the SELinux based ones require a VM,
because the tests need a kernel with SELinux support. Let's show how
to run the Fedora-based e2e tests locally and how to debug SPO at
the same time. Having [vagrant](https://www.vagrantup.com/downloads)
installed is a prerequisite. This section more-or-less follows the [github CI
workflow](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/.github/workflows/test.yml#L68),
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

### Distribution specific instructions: OpenShift
The fastest build-test loop on an OpenShift cluster is to push the SPO images
using `make push-openshift-dev` after each change to the SPO code and then
run the selected tests, e.g. to only run SELinux tests:
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
 - Instantiate the structure in the switch-case statement in `TestSuite`.

## Building the operator image with support for AppArmor

The AppArmor functionality is conditionally built based on a compilation tag,
to enable it an environment variable `APPARMOR_ENABLED` must be used and set to
`true`. By default, this is set to `false`.

Example:

`APPARMOR_ENABLED=true make image`

A full process of building, pushing it to a registry and deploying it into a cluster:

```sh
export IMAGE=<registry-and-image-name>:<label>

APPARMOR_ENABLED=true make image
docker push "${IMAGE}"

make deploy

SPO_NS=security-profiles-operator
kubectl -n $SPO_NS patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'

kubectl -n $SPO_NS patch deploy security-profiles-operator --type=merge -p '{"spec": {"template": {"spec": {"containers": [{"name":"security-profiles-operator", "image": "'$IMAGE'"}]}}}}'

kubectl apply -f examples/apparmorprofile.yaml
kubectl apply -f examples/pod-apparmor.yaml
```
