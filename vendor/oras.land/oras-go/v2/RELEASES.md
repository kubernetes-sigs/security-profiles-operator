# Releasing oras-go

Releases are created via a GitOps workflow. Merging a pull request with the
`release` label into `v2` automatically tags the commit and publishes the
GitHub Release. The pull request title supplies the version to tag.

## Steps

### 1. Create a release branch

The release branch needs at least one commit so GitHub will allow a PR to be
opened. It must live in `oras-project/oras-go`: the release workflow ignores
pull requests from forks, so merging a fork branch will not publish a release.

Use an empty commit as a lightweight marker. The branch may follow the usual
repository naming conventions because its name does not control the release:

```bash
git fetch upstream
git checkout -b chore/release-v2.7.0 upstream/v2
git commit --allow-empty -s -m "chore: prepare release v2.7.0"
git push upstream chore/release-v2.7.0
```

The release does not need to contain the changes being released — those are
already on `v2`. The PR is a trigger: when it merges, the workflow tags the
PR's `merge_commit_sha` (the exact commit that landed on `v2`), which includes
all prior work on the branch.

### 2. Open a pull request

Open a PR titled `release: v2.7.0` targeting the `v2` branch and add the
`release` label **before merging** - the release workflow triggers on the pull
request `closed` event, and that payload snapshots the labels as they were at
merge time, so labelling afterwards does nothing.

A release PR merged without the label tags nothing and cannot be re-triggered:
recovery is a fresh release PR.

Write the release notes directly in the PR description using the format from
prior releases:

```markdown
## New Features
...

## Bug Fixes
...

## Documentation
...

## Other Changes
...
```

The PR description becomes the GitHub Release body verbatim, so write it in
its final form.

### 3. Get approvals

Branch protection on `v2` requires approval from at least 3 of the 4 owners
listed in [OWNERS.md](OWNERS.md). Reviewers should verify:

- The target commit is correct
- The release notes are accurate and complete
- All CI checks pass

### 4. Merge

Merge the PR. The [release workflow](.github/workflows/release.yml)
automatically:

1. Extracts the version from the PR title (`release: v2.7.0` → `v2.7.0`)
2. Creates and pushes the git tag
3. Publishes the GitHub Release with the PR body as release notes

## Pre-releases

Tags containing `-alpha`, `-beta`, or `-rc` (e.g., `v2.7.0-rc.1`) are
automatically marked as pre-release on GitHub. Use the corresponding PR title,
for example `release: v2.7.0-rc.1`.

## Testing the workflow locally

Three levels of local validation are available without triggering a real release:

**1. Validate the goreleaser config:**
```bash
goreleaser check
```

**2. Validate workflow structure and job matching (dry run):**
```bash
act pull_request \
  -e .github/act/release-event.json \
  -W .github/workflows/release.yml \
  -n
```

**3. Run the workflow end-to-end with a fake token (Colima + cached actions required):**
```bash
act pull_request \
  -e .github/act/release-event.json \
  -W .github/workflows/release.yml \
  -s GITHUB_TOKEN=fake \
  --pull=false \
  --action-offline-mode \
  --container-daemon-socket -
```

This runs all steps up to and including version extraction (`version=vX.Y.Z` will
appear in the output). The `git push` step then fails with a permission error —
that is expected and confirms no tag was pushed. The mock event payload is at
`.github/act/release-event.json`; it carries the `release` label and a matching
title.

## Updating the documentation site

After a release, update [oras-www](https://github.com/oras-project/oras-www)
to reflect the new version. See the `CLAUDE.md` in that repository for the
exact steps.
