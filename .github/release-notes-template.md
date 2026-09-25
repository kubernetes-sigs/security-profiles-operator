<!--
Template for the hand-written part of a GitHub release body. Copy everything
below the line into the release, replace VERSION, write the summary paragraph,
and let GitHub generate the changelog underneath. See doc/release.md.
-->

---

Welcome to the VERSION release of the **security-profiles-operator**!

SUMMARY: one paragraph on what this release brings, for example the main
features, the most relevant fixes, or that it is a patch release. The general
usage and setup can be found [in our documentation][docs].

To install the operator, run:

```
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/VERSION/deploy/operator.yaml
```

The operator can also be installed [with helm][helm], and `spoc`, the official
Security Profiles Operator Command Line Interface, is attached to this release
for `amd64`, `arm64`, `ppc64le` and `s390x`.

All released artifacts are signed and the release assets carry SLSA build
provenance. [Verifying the released artifacts][verification] has the commands
for the container images, the binaries, the SBOM and the helm chart.

Feel free to provide us any kind of feedback in the official [Kubernetes Slack
#security-profiles-operator channel][slack].

[docs]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/VERSION/doc/README.md
[helm]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/VERSION/doc/installation.md#installation-using-helm
[verification]: https://github.com/kubernetes-sigs/security-profiles-operator/blob/VERSION/doc/verification.md
[slack]: https://kubernetes.slack.com/messages/security-profiles-operator
