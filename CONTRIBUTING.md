# Contributing guidelines

Welcome to Kubernetes. We are excited about the prospect of you joining our
[community](https://git.k8s.io/community)! The Kubernetes community abides by
the CNCF [code of conduct](code-of-conduct.md). Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of
fostering an open and welcoming community, we pledge to respect all people who
contribute through reporting issues, posting feature requests, updating
documentation, submitting pull requests or patches, and other activities._

## Getting started

We have full documentation on how to get started contributing here:

- [Contributor License Agreement](https://git.k8s.io/community/CLA.md)
  Kubernetes projects require that you sign a Contributor License Agreement
  (CLA) before we can accept your pull requests
- [Kubernetes Contributor
  Guide](https://git.k8s.io/community/contributors/guide) - Main contributor
  documentation, or you can just jump directly to the [contributing
  section](https://git.k8s.io/community/contributors/guide/contributing.md)
- [Contributor Cheat
  Sheet](https://git.k8s.io/community/contributors/guide/contributor-cheatsheet)
  - Common resources for existing developers

## Prerequisites

- [Go](https://go.dev/dl/) with the version of the `go` directive in
  [go.mod](go.mod).
- [podman](https://podman.io/docs/installation) or
  [docker](https://docs.docker.com/engine/install/) to build the container
  images.
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) version v1.30+.
- Access to a Kubernetes v1.30+ cluster.

For detailed development setup and build instructions, see [hacking.md](doc/hacking.md).

## Contributing steps

1. Submit an issue describing your proposed change to the repo in question.
1. The [repo owners](OWNERS) will respond to your issue promptly.
1. If your proposed change is accepted, and you haven't already done so, sign a Contributor License Agreement (see details above).
1. Fork the desired repo, develop and test your code changes.
1. Submit a pull request.

## What to do before submitting a pull request

Run the unit tests with `make test-unit` and the checks of
[verifying changes](doc/hacking.md#verifying-changes), which also lists the
checks that only run in CI. The e2e tests need a cluster, see
[running e2e tests](doc/hacking.md#running-e2e-tests). If a vulnerability
check fails, see
[vulnerability checks and assessments](doc/hacking.md#vulnerability-checks-and-assessments).
The [pull request template](.github/PULL_REQUEST_TEMPLATE.md) asks for the
kind of the change and a release note for user-facing changes.

## Where the CI tests are configured

1. See the [action files](.github/workflows) to check its tests, and the scripts used on it.
1. Note that the prow tests used in the CI are configured in [kubernetes-sigs/security-profiles-operator/security-profiles-operator-presubmits.yaml](https://github.com/kubernetes/test-infra/blob/master/config/jobs/kubernetes-sigs/security-profiles-operator/security-profiles-operator-presubmits.yaml).

## Mentorship

- [Mentoring Initiatives](https://git.k8s.io/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!

## Contact information

- [Slack channel](https://kubernetes.slack.com/messages/security-profiles-operator)
