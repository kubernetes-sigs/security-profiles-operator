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

# Creates the signed, annotated release tag for the version in the VERSION
# file on the current commit and verifies it, once the vx.y.z staging images
# are the ones of the commit. It does not push, the command to do so is
# printed at the end, with the remote of the upstream repository or REMOTE.
# Tags created in the GitHub UI are lightweight and unsigned, so releases are
# tagged with this script instead.

set -euo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT"

# shellcheck source=hack/lib/common.sh
source hack/lib/common.sh

VERSION="v$(cat VERSION)"
UPSTREAM=kubernetes-sigs/security-profiles-operator

# Whether a remote pushes to the upstream repository, over HTTPS or SSH, or a
# URL is the upstream repository. The push URL counts: a remote that fetches
# from upstream may have a push URL like no_push to prevent pushes.
is_upstream() {
    local url
    url="$(git remote get-url --push "$1" 2>/dev/null || echo "$1")"
    [[ "$url" =~ ^(https://|ssh://)?([^@/]+@)?github\.com[:/]$UPSTREAM(\.git)?/?$ ]]
}

# The tag has to be pushed to the upstream repository, which is often not
# origin, but a fork.
REMOTE="${REMOTE:-}"
if [[ -z "$REMOTE" ]]; then
    for remote in $(git remote); do
        if is_upstream "$remote"; then
            REMOTE="$remote"
            break
        fi
    done
fi

if [[ "$VERSION" == *-dev ]]; then
    echo "VERSION is the development version $VERSION, run hack/release.sh first" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "The tree is dirty, commit or stash the changes first" >&2
    exit 1
fi

if git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null; then
    echo "Tag $VERSION exists already" >&2
    exit 1
fi

# The release attests the images it builds from the tag, and kpromo pr
# promotes the ones the vx.y.z staging tags point to, so these have to be the
# images of this commit, see doc/release.md. Every staging image also gets the
# tag of its commit, which ends with -g<abbreviated commit>. Staging builds of
# two commits can run at the same time, the vx.y.z tags point to the images of
# the one which finished last.
CRANE=$(crane_bin)
COMMIT=$(git rev-parse HEAD)
STAGING_IMAGES=(
    security-profiles-operator
    "${IMAGE_ARCHES[@]/#/security-profiles-operator-}"
    security-profiles-operator-bundle
    security-profiles-operator-catalog
)
for image in "${STAGING_IMAGES[@]}"; do
    repo="$STAGING_REGISTRY/$image"
    tags=$("$CRANE" ls "$repo")
    commit_tag=''
    while read -r tag; do
        if [[ -n "$tag" && "$COMMIT" == "${tag##*-g}"* ]]; then
            commit_tag="$tag"
        fi
    done <<<"$(grep -E -- "-g${COMMIT:0:7}[0-9a-f]*$" <<<"$tags" || true)"
    if [[ -z "$commit_tag" ]]; then
        echo "$repo has no image of $COMMIT, wait for its staging build" >&2
        exit 1
    fi
    version_digest=$("$CRANE" digest "$repo:$VERSION")
    commit_digest=$("$CRANE" digest "$repo:$commit_tag")
    if [[ "$version_digest" != "$commit_digest" ]]; then
        echo "$repo:$VERSION is not the image of $COMMIT ($commit_tag)" >&2
        exit 1
    fi
done

echo "Tagging $(git rev-parse --short HEAD) as $VERSION"
git tag -s -m "Security Profiles Operator $VERSION" "$VERSION"
git verify-tag "$VERSION"

if [[ -z "$REMOTE" ]]; then
    REMOTE="git@github.com:$UPSTREAM.git"
    echo "No remote pushes to $UPSTREAM, set REMOTE to use one" >&2
elif ! is_upstream "$REMOTE"; then
    echo "WARNING: The remote $REMOTE doesn't push to $UPSTREAM" >&2
fi
echo "Done. Push the tag to $UPSTREAM right away with: git push $REMOTE $VERSION"
echo "A staging build of another commit with the same VERSION, which only a Tide"
echo "batch or an override of the release freeze gives, would still move the"
echo "$VERSION staging tags until the tag is pushed, so make sure that none runs."
echo "Then create the release from the pushed tag. Don't let the GitHub UI create"
echo "the tag, that would be a lightweight, unsigned one."
