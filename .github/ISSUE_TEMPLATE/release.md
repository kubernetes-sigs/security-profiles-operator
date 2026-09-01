---
name: Release
about: Track a new release
labels: kind/feature
title: "Release v"

---

Tracking issue for the v{VERSION} release.

#### Prerequisites

<!-- List any PRs or issues that must be merged before cutting the release -->

None

#### Release checklist

- [ ] Run `./hack/release.sh {VERSION}` and merge version bump PR
- [ ] Verify [`post-security-profiles-operator-push-image` prow job](https://prow.k8s.io/?job=post-security-profiles-operator-push-image) succeeds
- [ ] Create and merge image promotion PR in [k8s.io](https://github.com/kubernetes/k8s.io) via `kpromo`
- [ ] Create GitHub release with auto-generated release notes (use the template below)
- [ ] Run `./hack/back-to-dev.sh` and create back-to-dev PR
- [ ] Create OperatorHub community-operators PR
- [ ] Send release announcement to #security-profiles-operator Slack channel

#### Release notes template

<!-- Replace {VERSION} with the actual version, e.g. 1.0.2 -->

<details>
<summary>Click to expand</summary>

````markdown
Welcome to the v{VERSION} release of the **security-profiles-operator**!

<!-- Add a short summary of the release here -->

The general usage and setup can be found [in our documentation][0].

To install the operator, run:

```
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v{VERSION}/deploy/operator.yaml
```

You can also verify the container image signature by using [cosign][1]:

```
$ cosign verify \
    --certificate-identity krel-trust@k8s-releng-prod.iam.gserviceaccount.com \
    --certificate-oidc-issuer https://accounts.google.com \
    registry.k8s.io/security-profiles-operator/security-profiles-operator:v{VERSION}
```

Besides the operator image, we now also ship `spoc`, the official Security Profiles Operator Command Line Interface! Binaries for `amd64`, `arm64`, `ppc64le` and `s390x` are attached to this release.

To verify the signature of `spoc`, download all release artifacts and run for `amd64` (works in the same way for `arm64`, `ppc64le` and `s390x`):

```
$ cosign verify-blob \
    --certificate-identity sgrunert@redhat.com \
    --certificate-oidc-issuer https://github.com/login/oauth \
    --bundle spoc.amd64.bundle \
    spoc.amd64
```

We also provide `.sha512` sum files for the binaries.

Feel free to provide us any kind of feedback in the official [Kubernetes Slack #security-profiles-operator channel][2].

[0]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v{VERSION}/installation-usage.md
[1]: https://github.com/sigstore/cosign
[2]: https://app.slack.com/client/T09NY5SBT/C013FQNB0A2
````

</details>
