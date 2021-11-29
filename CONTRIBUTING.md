# Contributing Guidelines

Welcome to Kubernetes. We are excited about the prospect of you joining our
[community](https://git.k8s.io/community)! The Kubernetes community abides by
the CNCF [code of conduct](code-of-conduct.md). Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of
fostering an open and welcoming community, we pledge to respect all people who
contribute through reporting issues, posting feature requests, updating
documentation, submitting pull requests or patches, and other activities._

## Getting Started

We have full documentation on how to get started contributing here:

<!---
If your repo has certain guidelines for contribution, put them here ahead of the
general k8s resources
-->

- [Contributor License Agreement](https://git.k8s.io/community/CLA.md)
  Kubernetes projects require that you sign a Contributor License Agreement
  (CLA) before we can accept your pull requests
- [Kubernetes Contributor
  Guide](https://git.k8s.io/community/contributors/guide) - Main contributor
  documentation, or you can just jump directly to the [contributing
  section](https://git.k8s.io/community/contributors/guide#contributing)
- [Contributor Cheat
  Sheet](https://git.k8s.io/community/contributors/guide/contributor-cheatsheet)
  - Common resources for existing developers

## Prerequisites

- [go](https://golang.org/dl/) version v1.15+.
- [docker](https://docs.docker.com/install/) version 17.03+.
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) version v1.19+.
- Access to a Kubernetes v1.19+ cluster.

## Contributing steps

1. Submit an issue describing your proposed change to the repo in question.
1. The [repo owners](OWNERS) will respond to your issue promptly.
1. If your proposed change is accepted, and you haven't already done so, sign a Contributor License Agreement (see details above).
1. Fork the desired repo, develop and test your code changes.
1. Submit a pull request.

## What to do before submitting a pull request

Following the targets that can be used to test your changes locally.

| Command             | Description                          | Is called in the CI? |
| ------------------- | ------------------------------------ | -------------------- |
| make test-unit      | Runs go tests                        | yes                  |
| make test-e2e       | Runs the CI e2e tests locally        | yes                  |
| make verify-go-lint | Run [golangci][golangci] lint checks | yes                  |
| make verify         | Run all verification checks          | yes                  |

## Where the CI Tests are configured

1. See the [action files](.github/workflows) to check its tests, and the scripts used on it.
1. Note that the prow tests used in the CI are configured in [kubernetes-sigs/security-profiles-operator/security-profiles-operator-presubmits.yaml](https://github.com/kubernetes/test-infra/blob/master/config/jobs/kubernetes-sigs/security-profiles-operator/security-profiles-operator-presubmits.yaml).

## Mentorship

- [Mentoring Initiatives](https://git.k8s.io/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!

<!---
Custom Information - if you're copying this template for the first time you can
add custom content here.
-->

## Contact Information

- [Slack channel](https://kubernetes.slack.com/messages/security-profiles-operator)
