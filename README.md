# Kubernetes Security Profiles Operator

[![build](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/build.yml/badge.svg)](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/build.yml)
[![test](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/test.yml/badge.svg)](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/test.yml)
[![coverage](https://codecov.io/gh/kubernetes-sigs/security-profiles-operator/branch/main/graph/badge.svg?token=37VIWSZ1ZT)](https://codecov.io/gh/kubernetes-sigs/security-profiles-operator)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5368/badge)](https://bestpractices.coreinfrastructure.org/projects/5368)
[![OCI security profiles](https://img.shields.io/badge/oci%3A%2F%2F-security%20profiles-blue?logo=kubernetes&logoColor=white)](doc/cli.md#pushing-profiles-for-container-runtimes)

The _Security Profiles Operator_ (SPO) is an out-of-tree Kubernetes enhancement which aims to make
it easier to create and use SELinux, seccomp and AppArmor security profiles in Kubernetes clusters.

The [documentation](doc/README.md) covers the installation, the profiles, the
`spoc` command line interface, troubleshooting and the development of SPO. The
released container images are available below
`registry.k8s.io/security-profiles-operator`, see
[verifying the released artifacts](doc/verification.md#container-image).

## Quick start

Install [cert-manager](https://cert-manager.io), which is not needed on
OpenShift:

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl --namespace cert-manager wait --for condition=available deployment --all
```

Install the operator from the manifest of the
[latest release](https://github.com/kubernetes-sigs/security-profiles-operator/releases/latest),
where `VERSION` is its version without the `v` prefix:

```sh
VERSION=x.y.z
kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/deploy/operator.yaml"
```

Once `kubectl -n security-profiles-operator get spod spod` reports the state
`Running`, create the example seccomp profiles and check that they got
installed on the nodes:

```sh
$ kubectl apply -f "https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v${VERSION}/examples/seccompprofile.yaml"
$ kubectl get sp
NAME                               STATUS      AGE
profile-allow-unsafe               Installed   20s
profile-block-all                  Installed   20s
profile-complain-block-high-risk   Installed   20s
profile-complain-unsafe            Installed   20s
```

[Use Seccomp profile](doc/profiles.md#use-seccomp-profile) shows how a pod
uses them.

## Installation methods

- [Release manifest](doc/installation.md#install-operator), as in the quick
  start above.
- [Helm chart](doc/installation.md#installation-using-helm), attached to each
  release and published on `registry.k8s.io`.
- [OLM](doc/installation.md#installation-using-olm-from-operatorhubio), from
  operatorhub.io or from the
  [upstream catalog](doc/installation.md#installation-using-olm-using-upstream-catalog-and-bundle).
- [OpenShift](doc/installation.md#openshift), through OperatorHub. OpenShift
  needs no cert-manager.

## Features

This is the parity of features across various security profiles supported by the SPO:

|                                           | Seccomp | SELinux | AppArmor |
|-------------------------------------------|---------|---------|----------|
| Profile CRD                               |   Yes   | Yes     | Yes      |
| Install profiles in cluster               |   Yes   | Yes     | Yes      |
| Remove unused profiles from cluster       |   Yes   | Yes     | Yes      |
| Profile Recording (audit logs)            |   Yes   | Yes     | No       |
| Profile Recording (eBPF)                  |   Yes   | No      | Yes      |
| Profile Binding to container images       |   Yes   | Yes     | Yes      |
| Audit log enrichment                      |   Yes   | Yes     | Yes      |
| Audit In-Pod Activity JSON log enrichment |   Yes   | No      | No       |

For information about the security model and what permissions each feature requires,
refer to SPO's [security model](doc/security-model.md).

## Resources

The motivation behind the project can be found in the corresponding [RFC][0].

The operator runs as a deployment in the cluster and manages daemon pods on
each node. These daemon pods handle profile installation, recording, and
enforcement for seccomp, SELinux, and AppArmor. The
[documentation](doc/README.md#architecture) describes the architecture and
links the user stories, personas and guides.

[0]: doc/RFC.md

Related Kubernetes Enhancement Proposals (KEPs) which have direct influence on
this project:

- [Promote seccomp to GA][1]
- [Add ConfigMap support for seccomp custom profiles][2]
- [Add KEP to create seccomp built-in profiles and add complain mode][3]

Next to those KEPs, here are existing approaches for security profiles in
the Kubernetes world:

- [AppArmor Loader][4]
- [OpenShift's Machine config operator, in charge of file management and security profiles on hosts][5]
- [seccomp-config][6]

[1]: https://github.com/kubernetes/enhancements/pull/1148
[2]: https://github.com/kubernetes/enhancements/pull/1269
[3]: https://github.com/kubernetes/enhancements/pull/1257
[4]: https://github.com/kubernetes/kubernetes/tree/c30da3839c8e13fdff59ef5115e982362b2c90ed/test/images/apparmor-loader
[5]: https://github.com/openshift/machine-config-operator/tree/master/docs
[6]: https://github.com/UKHomeOffice/seccomp-config

## Community, discussions, contributions, and support

If you're interested in contributing to SPO, please see the [developer focused document](doc/hacking.md).

We schedule a monthly meeting every last Thursday of a month.

- [Meeting Notes][8]

[8]: https://docs.google.com/document/d/1FQHYdyd7PTCi7_Vd8erPS4nztp0blvivK87HhXqz4uc/edit?usp=sharing

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack #security-profiles-operator](https://kubernetes.slack.com/messages/security-profiles-operator)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/dev)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
