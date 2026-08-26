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
- [ ] Create GitHub release with release notes
- [ ] Run `./hack/back-to-dev.sh` and create back-to-dev PR
- [ ] Create OperatorHub community-operators PR
- [ ] Send release announcement to #security-profiles-operator Slack channel
