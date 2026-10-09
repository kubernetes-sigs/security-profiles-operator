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

# Moves the floating tags latest and main of the toolchain image IMAGE to
# DIGEST, which the build-image job of the build workflow pushed for the
# checked out commit. Every push to main runs on its own and the build takes
# up to three hours, so the runs can finish out of order. A later commit of
# main which changes the inputs of the image, see build-image-inputs.sh, has a
# run which builds the image and moves the tags, so an earlier run leaves them
# alone. Later commits which leave the inputs alone keep the image current.
# The commit tag stays, and build-image-sign signs DIGEST either way.

set -euo pipefail

# shellcheck source=hack/ci/build-image-inputs.sh
source "$(dirname "${BASH_SOURCE[0]}")/build-image-inputs.sh"

: "${IMAGE:?}" "${DIGEST:?}"
TAGS=(latest main)

git fetch --no-tags --depth=1 origin refs/heads/main
files="$(git diff --name-only HEAD FETCH_HEAD)"
if changed="$(grep -E "$BUILD_IMAGE_INPUTS" <<<"$files")"; then
    echo "Not moving the tags ${TAGS[*]}, later commits of main change the inputs of the image:"
    echo "$changed"
    exit 0
fi

args=()
for tag in "${TAGS[@]}"; do
    args+=(--tag "$IMAGE:$tag")
done
# A single source gets copied as is with --prefer-index=false, so the tags
# point to the digest that build-image-sign signs.
docker buildx imagetools create --prefer-index=false "${args[@]}" "$IMAGE@$DIGEST"

for tag in "${TAGS[@]}"; do
    digest="$(docker buildx imagetools inspect "$IMAGE:$tag" --format '{{json .Manifest.Digest}}' | tr -d '"')"
    if [[ "$digest" != "$DIGEST" ]]; then
        echo "$IMAGE:$tag points to $digest instead of $DIGEST" >&2
        exit 1
    fi
    echo "Moved $IMAGE:$tag to $DIGEST"
done
