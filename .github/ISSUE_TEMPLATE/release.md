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

See [`doc/release.md`](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/doc/release.md) for the details of every step.

- [ ] Run `./hack/release.sh {VERSION}` and merge version bump PR
- [ ] Add the `tide/merge-blocker` label to this issue right after the version bump PR is merged (required: a PR merged before the promotion moves the `v{VERSION}` staging tags, and images without the GitHub provenance of the release, with level 1 provenance only, would get promoted; remove it only after the promotion)
- [ ] Verify [`post-security-profiles-operator-push-image` prow job](https://prow.k8s.io/?job=post-security-profiles-operator-push-image) succeeds
- [ ] Verify that the [`image-reproducible` workflow](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/image-reproducible.yml) succeeded for the push of the version bump commit to `main`
- [ ] Tag the release with `./hack/tag-release.sh` and push the tag to `kubernetes-sigs/security-profiles-operator` with the command it prints (if a PR got merged after the version bump anyway, tag the newest commit of `main` while its `VERSION` is still `{VERSION}` and the `v{VERSION}` staging tags point to its images)
- [ ] Create the GitHub release from the pushed tag as pre-release, never letting the GitHub UI create the tag, with auto-generated release notes below the text of [`.github/release-notes-template.md`](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/.github/release-notes-template.md)
- [ ] Verify that the [`image-reproducible` workflow](https://github.com/kubernetes-sigs/security-profiles-operator/actions/workflows/image-reproducible.yml) of the release succeeds and attaches `images.intoto.jsonl`
- [ ] Verify [`post-security-profiles-operator-push-release-artifacts` prow job](https://prow.k8s.io/?job=post-security-profiles-operator-push-release-artifacts) succeeds
- [ ] Create the image promotion PR in [k8s.io](https://github.com/kubernetes/k8s.io) via `kpromo pr --staging-repo us-central1-docker.pkg.dev/k8s-staging-images/sp-operator`, within 90 days of the version bump
- [ ] Before merging the image promotion PR, check that its per-arch image digests are the subjects of `images.intoto.jsonl`, then merge it
- [ ] Check that the promoter carried the attestations to `registry.k8s.io` and wrote the verification summaries
- [ ] Set the GitHub release as latest release, and verify that the `spoc-reproducible` workflow succeeds (re-run it if the release was published as full release before the promotion)
- [ ] Remove the `tide/merge-blocker` label from this issue
- [ ] Run `./hack/back-to-dev.sh` and create back-to-dev PR
- [ ] Create OperatorHub community-operators PR
- [ ] Send release announcement to #security-profiles-operator Slack channel
