# Installation

[Documentation](README.md) | **Installation** | [Configuration](configuration.md) | [Profiles](profiles.md) | [Recording](recording.md) | [CLI](cli.md) | [Metrics](metrics.md) | [Troubleshooting](troubleshooting.md)

<!-- toc -->
- [Requirements](#requirements)
- [Installation using the release manifest](#installation-using-the-release-manifest)
- [Installation using Helm](#installation-using-helm)
  - [Chart values](#chart-values)
  - [CRDs of the chart](#crds-of-the-chart)
- [Installation using OLM](#installation-using-olm)
  - [From operatorhub.io](#from-operatorhubio)
  - [From the upstream catalog](#from-the-upstream-catalog)
- [Installation on OpenShift](#installation-on-openshift)
- [Installation on AKS](#installation-on-aks)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
<!-- /toc -->

## Requirements

The operator requires Kubernetes v1.30 or later. The operator container image
consists of an image manifest which supports the architectures `amd64`,
`arm64` and `ppc64le`.

The operator needs [cert-manager](https://cert-manager.io) for the
certificates of its webhook and metrics endpoints, except on
[OpenShift](#installation-on-openshift), whose service CA provides them.
Install it before the operator:

```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl --namespace cert-manager wait --for condition=available deployment --all
```

The Deployments can be available before the cert-manager webhook serves
requests. [`cmctl check api --wait=2m`](https://cert-manager.io/docs/installation/verify/)
waits for it.

The commands on this page use `VERSION` for the version of the desired
[release](https://github.com/kubernetes-sigs/security-profiles-operator/releases)
without the `v` prefix:

```shell
VERSION=x.y.z
```

## Installation using the release manifest

Apply the operator manifest of the release:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/operator.yaml
```

The manifests on the `main` branch reference the development images from the
staging registry and are not meant for production use.

The operator then creates the `spod` SPOD in the `security-profiles-operator`
namespace, which reports the state `Running` once the daemon runs on all nodes:

```console
$ kubectl -n security-profiles-operator get spod spod
NAME   STATE     READY   AGE
spod   Running   True    5m
```

## Installation using Helm

A Helm chart is attached to each
[GitHub release](https://github.com/kubernetes-sigs/security-profiles-operator/releases).
The chart does not install cert-manager, see the
[requirements](#requirements), and does not manage the namespace, so create the
namespace beforehand. The daemon runs privileged, so the namespace needs the
privileged Pod Security Standard:

```shell
kubectl create namespace security-profiles-operator
kubectl label namespace security-profiles-operator \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  --overwrite=true
```

Then install the chart from the release URL, or from a downloaded file:

```shell
helm install security-profiles-operator --namespace security-profiles-operator \
  https://github.com/kubernetes-sigs/security-profiles-operator/releases/download/v${VERSION}/security-profiles-operator-${VERSION}.tgz
```

To install into another namespace, create and label it as shown above and pass
it to `--namespace`. `--create-namespace` creates it without the Pod Security
labels, so the admission rejects the privileged pods of the daemon unless the
cluster allows them by default.

To verify a downloaded chart archive before installing it, see
[verifying the released artifacts](verification.md#helm-chart), whose commands
expect `VERSION` with the `v` prefix.

The chart is also published as OCI artifact to `registry.k8s.io`. Install it
with the same preparation from there:

```shell
helm install security-profiles-operator --namespace security-profiles-operator \
  oci://registry.k8s.io/security-profiles-operator/charts/security-profiles-operator \
  --version ${VERSION}
```

The OCI chart holds the release archive above and has the same SLSA build
provenance, see
[verifying the released artifacts](verification.md#oci-artifacts-on-registryk8sio).
That doesn't apply to the chart of v1.1.0, and the releases before it have no
OCI chart, see [older releases](verification.md#older-releases).

### Chart values

The [values](../deploy/helm/values.yaml) of the chart are documented in its
[README](../deploy/helm/README.md) and validated against its
[schema](../deploy/helm/values.schema.json), so a misspelled or unknown value
fails the installation. Among others:

- `kubeletDir` sets the kubelet root directory of the nodes, where the seccomp
  profiles get installed, `/var/lib/kubelet` by default. See
  [Configure a custom kubelet root directory](configuration.md#configure-a-custom-kubelet-root-directory).
- `podDisruptionBudget` creates a PodDisruptionBudget for the operator
  deployment, which keeps `minAvailable` replicas (default `1`) running during
  voluntary disruptions like node drains. With a single replica
  (`replicaCount: 1`), the default blocks the drain of its node, so lower
  `minAvailable` to `0` or disable the budget with
  `podDisruptionBudget.enabled=false` then.
- `topologySpreadConstraints` spreads the operator replicas across nodes
  (`kubernetes.io/hostname`) and zones (`topology.kubernetes.io/zone`) where
  possible (`whenUnsatisfiable: ScheduleAnyway`). Constraints without a
  `labelSelector` get the selector labels of the operator pods, set the list
  to `[]` to drop them.
- `priorityClassName` sets the priority class of the operator pods,
  `system-cluster-critical` by default. Set it to `""` for none, see
  [priority classes](configuration.md#set-a-custom-priority-class-for-the-daemon).
- `imagePullSecrets` lists the secrets for pulling the images from a private
  registry, like `[{name: my-pull-secret}]`. They apply to the operator
  deployment and, through `spec.imagePullSecrets` of the SPOD, to the daemon
  and the webhook. The secrets have to exist in the release namespace.
- `spoImage.digest` pins the operator image by digest, the tag only applies
  without one.
- `extraEnv` sets environment variables of the operator, see
  [environment variables](configuration.md#environment-variables-of-the-operator).
- `spod.spec` takes any field of the `SecurityProfilesOperatorDaemon` spec
  and merges it over the fields which the dedicated values like
  `enableAppArmor` render. Objects get merged field by field, every other
  value, lists included, replaces the rendered one. For example
  `--set spod.spec.enableMemoryOptimization=true` or
  `--set spod.spec.scheduling.priorityClassName=my-priority-class`.

The operator deployment of the release manifests, like
[`deploy/operator.yaml`](../deploy/operator.yaml), has the same
PodDisruptionBudget, topology spread constraints and priority class.

```shell
helm install security-profiles-operator --namespace security-profiles-operator \
  --set kubeletDir=/var/lib/k0s/kubelet \
  --set podDisruptionBudget.minAvailable=2 \
  --set 'imagePullSecrets[0].name=my-pull-secret' \
  --set spod.spec.enableMemoryOptimization=true \
  https://github.com/kubernetes-sigs/security-profiles-operator/releases/download/v${VERSION}/security-profiles-operator-${VERSION}.tgz
```

The chart renders the SPOD from its values, so a `helm upgrade` can revert the
SPOD fields which got patched with `kubectl` since, for example when the chart
changes their value. Set them through the values instead.

### CRDs of the chart

The chart installs the CRDs from its `crds` directory, which Helm does not
template. Helm does not upgrade or delete CRDs, see the
[Helm documentation](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/)
and [Upgrading](#upgrading) for how to update them.

## Installation using OLM

The operator can be installed with version 0 of the
[Operator Lifecycle Manager (OLM)](https://olm.operatorframework.io/), which
uses `CatalogSource` and `Subscription` objects. First make sure that OLM
itself is [installed](https://olm.operatorframework.io/docs/getting-started/).

### From operatorhub.io

[operatorhub.io](https://operatorhub.io/operator/security-profiles-operator)
publishes the released versions of the operator. Install it from there with
the provided manifest:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/examples/olm/operatorhub-io.yaml
```

The operator then runs in the `security-profiles-operator` namespace. Its
`OperatorGroup` targets all namespaces, see
[Restrict the operator when installing using OLM](configuration.md#restrict-the-operator-when-installing-using-olm)
to restrict the operator. To troubleshoot the installation, check the state of
the `Subscription`, `ClusterServiceVersion` and `InstallPlan` objects in the
`security-profiles-operator` namespace:

```shell
kubectl -n security-profiles-operator get ip,csv,sub
```

### From the upstream catalog

The project also builds bundles and catalogs for the released versions and
after every commit to the `main` branch. Install a released version with:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/examples/olm/install-resources.yaml
```

The same file on the `main` branch installs the latest development catalog from
the staging registry.

The catalog of a release only holds the bundle of that release, and OLM does
not poll it for updates. To upgrade, point the `CatalogSource` to the catalog
of the new release, see [Upgrading](#upgrading).

## Installation on OpenShift

OpenShift needs no cert-manager, its service CA injects the certificates.
OpenShift ships the operator in its Red Hat catalog, install it from the
operator catalog of the web console. The [metrics](metrics.md) of an
installation from the Red Hat catalog get scraped without further
configuration.

To install the upstream releases from operatorhub.io instead, create a
`CatalogSource` for it:

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: operatorhubio
  namespace: openshift-marketplace
spec:
  displayName: Community Operators
  image: quay.io/operatorhubio/catalog:latest
  publisher: OperatorHub.io
  sourceType: grpc
```

The Security Profiles Operator then shows up in the operator catalog of the web
console, published by OperatorHub.io.

The [upstream catalog](#from-the-upstream-catalog) works on OpenShift too, but
OpenShift deploys the OLM catalogs into the `openshift-marketplace` namespace,
so replace the namespaces before applying the manifest:

```shell
curl -sSfL https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/examples/olm/install-resources.yaml |
  sed "s#olm#openshift-marketplace#g" | oc apply -f -
```

See also the [notes on OpenShift and SCCs](troubleshooting.md#notes-on-openshift-and-sccs),
[SELinux profiles on OpenShift](profiles.md#use-a-selinux-profile-on-openshift)
and the [OpenShift webhook options](configuration.md#configure-the-webhooks)
for `oc debug node`.

## Installation on AKS

On an [AKS cluster](https://azure.microsoft.com/en-us/products/kubernetes-service/#overview),
[configure the webhooks](configuration.md#configure-the-webhooks) to skip the
namespaces with the
[`control-plane`](https://learn.microsoft.com/en-us/azure/aks/faq#can-i-use-admission-controller-webhooks-on-aks-)
label. The `namespaceSelector` replaces the default one of the webhook, so it
has to keep the `spo.x-k8s.io/enable-binding` and
`spo.x-k8s.io/enable-recording` requirements, otherwise the webhooks apply to
every namespace. The patch replaces all entries of `webhook.options`:

```shell
kubectl -n security-profiles-operator patch spod spod --type=merge \
  -p='{"spec":{"webhook":{"options":[{"name":"binding.spo.io","namespaceSelector":{"matchExpressions":[{"key":"spo.x-k8s.io/enable-binding","operator":"Exists"},{"key":"control-plane","operator":"DoesNotExist"}]}},{"name":"recording.spo.io","namespaceSelector":{"matchExpressions":[{"key":"spo.x-k8s.io/enable-recording","operator":"Exists"},{"key":"control-plane","operator":"DoesNotExist"}]}}]}}}'
```

Afterwards, check that the SPOD got patched successfully by ensuring the
`Running` state:

```console
$ kubectl -n security-profiles-operator get spod spod
NAME   STATE     READY   AGE
spod   Running   True    5m
```

## Upgrading

Read the release notes of every release between the installed one and the
target release before upgrading. Upgrades from releases before v1.0.0 have to
go through the latest v1.0.x release first, see the
[Migration Guide](migration-guide-v1.md).

For installations from the release manifests, apply the manifest of the new
release:

```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/operator.yaml
```

For Helm installations, apply the CRDs of the new release before upgrading the
chart, because Helm never updates the CRDs of an installed chart:

```shell
kubectl apply --server-side --force-conflicts -f \
  "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/helm/crds/crds.yaml"
helm upgrade security-profiles-operator --namespace security-profiles-operator \
  https://github.com/kubernetes-sigs/security-profiles-operator/releases/download/v${VERSION}/security-profiles-operator-${VERSION}.tgz
```

OLM upgrades its installations according to the `installPlanApproval` of their
`Subscription`, including the CRDs. The operatorhub.io catalog gets the new
releases on its own. The [upstream catalog](#from-the-upstream-catalog) of a
release only holds that release, so point its `CatalogSource` to the catalog of
the new release (`openshift-marketplace` instead of `olm` on OpenShift):

```shell
kubectl -n olm patch catalogsource security-profiles-operator --type merge \
  -p '{"spec":{"image":"registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"${VERSION}"'"}}'
```

## Uninstalling

To uninstall, remove the bindings, recordings and profiles before removing the
rest of the operator, so that the operator can remove the installed profiles
from the nodes:

```shell
kubectl delete profilebindings --all --all-namespaces
kubectl delete profilerecordings --all --all-namespaces
kubectl delete seccompprofiles --all
kubectl delete selinuxprofiles --all
kubectl delete rawselinuxprofiles --all
kubectl delete apparmorprofiles --all
```

Profiles that are still used by running pods are only removed once those pods
are gone. Then remove the operator with the manifest it was installed from:

```shell
kubectl delete -f "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/operator.yaml"
```

For Helm installations, uninstall the release instead, and delete the
namespace which was created before the installation, because Helm leaves the
resources in place which the operator creates at runtime.
`helm list --all --all-namespaces` shows the namespace of the release:

```shell
helm uninstall --namespace security-profiles-operator security-profiles-operator
kubectl delete namespace security-profiles-operator
```

For OLM installations, remove the `Subscription` and `ClusterServiceVersion`
instead, and then the namespace of the operator. OLM only removes what the
bundle ships, while the operator creates the `spod` DaemonSet, the webhook
Deployment and their services, certificates and service monitor at runtime.
They keep running without the operator until the namespace is deleted:

```shell
kubectl delete namespace security-profiles-operator
```

Neither Helm nor OLM removes the CRDs, which can be deleted afterwards if no
profiles should be kept:

```shell
kubectl get crds -o name | grep security-profiles-operator.x-k8s.io | xargs kubectl delete
```

The operator creates some cluster scoped admission resources at runtime, which
are not part of every manifest: the `kubectl` manifests remove both webhook
configurations, the Helm chart only the mutating one and OLM neither, and some
admission policies are not part of any manifest. Remove them once the operator
is gone, because a running operator recreates them:

```shell
kubectl delete validatingadmissionpolicies,validatingadmissionpolicybindings -l app=security-profiles-operator
kubectl delete mutatingwebhookconfiguration spo-mutating-webhook-configuration --ignore-not-found
kubectl delete validatingwebhookconfiguration spo-validating-webhook-configuration --ignore-not-found
```

Without the operator, a remaining webhook configuration makes the API server
reject or delay the requests which it matches, for example the pods in
namespaces labeled for binding or recording.
