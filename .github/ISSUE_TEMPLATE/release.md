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

Besides the operator image, we also ship `spoc`, the official Security Profiles Operator Command Line Interface. Binaries for `amd64`, `arm64`, `ppc64le` and `s390x` are attached to this release, together with their signatures, `.sha512` sums, the `spoc.spdx.json` SBOM and the `spoc.intoto.jsonl` SLSA build provenance.

The helm chart is available as OCI artifact as well:

```
$ helm install security-profiles-operator \
    --namespace security-profiles-operator \
    oci://registry.k8s.io/security-profiles-operator/charts/security-profiles-operator \
    --version {VERSION}
```

See the [installation guide][0] for the namespace preparation. The chart archive attached to this release is signed and has SLSA build provenance as well.

All release artifacts are signed with [Sigstore][1]. The [verification guide][2] has the commands to verify the signatures and the provenance.

Feel free to provide us any kind of feedback in the official [Kubernetes Slack #security-profiles-operator channel][3].

[0]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v{VERSION}/installation.md
[1]: https://www.sigstore.dev
[2]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/v{VERSION}/verification.md
[3]: https://app.slack.com/client/T09NY5SBT/C013FQNB0A2
````

</details>
