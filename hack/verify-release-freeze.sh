#!/usr/bin/env bash
# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Fails pull requests while a release is in progress, from the merge of the
# version bump until the back-to-dev PR, see doc/release.md. The VERSION file
# of the base branch names the release then instead of a -dev version. Every
# build of main tags its staging images with that version, so a commit merged
# in between would move the vx.y.z staging tags, which kpromo pr promotes. Only
# pull requests which change VERSION pass, like the back-to-dev PR, or one
# which fixes a wrong release version.
#
# Prow presubmits test the pull request merged into the commit PULL_BASE_SHA
# of the base branch PULL_BASE_REF, RELEASE_FREEZE_BASE overrides it. Releases are cut from
# main, so pull requests to other branches pass. Tide retests a pull request whose
# tests ran on an older commit of the base branch before merging it, so a
# pull request which passed before the version bump gets checked again. Runs
# without a base commit, like make verify outside of Prow, pass.
#
# A Tide batch with the version bump still passes, it runs on the -dev base.
# Tide merges the pull requests of a batch one by one, so the staging build of
# one merged after the version bump can move the vx.y.z tags before the
# release is tagged. hack/tag-release.sh only tags the commit whose images
# they point to then. Failing such batches would stall Tide, which retries a
# failed batch instead of merging its pull requests one by one.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [[ -n "${PULL_BASE_REF:-}" && "$PULL_BASE_REF" != main ]]; then
    echo "The base branch is $PULL_BASE_REF, releases are cut from main"
    exit 0
fi

BASE="${RELEASE_FREEZE_BASE:-${PULL_BASE_SHA:-}}"
if [[ -z "$BASE" ]]; then
    echo "No base commit to compare VERSION with, set RELEASE_FREEZE_BASE or PULL_BASE_SHA to check it"
    exit 0
fi

BASE_VERSION=$(git show "$BASE:VERSION")
VERSION=$(cat VERSION)

if [[ "$BASE_VERSION" == *-dev ]]; then
    echo "The base branch is at the development version $BASE_VERSION"
    exit 0
fi

if [[ "$VERSION" != "$BASE_VERSION" ]]; then
    echo "The base branch is at the release $BASE_VERSION, this change moves VERSION to $VERSION"
    exit 0
fi

cat >&2 <<EOF
The base branch is at the release $BASE_VERSION, which is in progress until the
back-to-dev PR sets a -dev version again. A commit merged before that moves the
v$BASE_VERSION staging tags to images the release didn't attest, see
doc/release.md. Retest this pull request after the back-to-dev PR is merged.
EOF
exit 1
