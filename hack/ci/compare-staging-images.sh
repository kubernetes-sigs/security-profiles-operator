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

# Compares the per-arch image digests in build/image-digests and the bundle
# and catalog digests in build/metadata-image-digests, which
# `PUSH=false hack/image-cross.sh` wrote, with the staging images Cloud Build
# pushed for the same commit. Cloud Build tags them vYYYYMMDD-<git describe>,
# so the staging tags of the commit end with -g<abbreviated commit>. The
# staging build runs at the same time as this job, the script waits up to
# STAGING_WAIT seconds for its manifest list. A missing staging image of the
# commit fails like a different digest: the image-reproducible workflow only
# compares on pushes to main, where Cloud Build pushes an image for every
# commit, so a missing one means that its build failed or took too long.

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

REGISTRY=https://us-central1-docker.pkg.dev/v2/k8s-staging-images/sp-operator
STAGING_WAIT=${STAGING_WAIT:-2700}
COMMIT=$(git rev-parse HEAD)
JQ=$(jq_bin)

# The registry allows anonymous reads.
registry_get() {
    curl -sSfL --retry 3 \
        -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' \
        "$REGISTRY/$1"
}

# The staging tags of the commit, of the manifest list, which Cloud Build
# pushes after the per-arch images, from the tag list of its repository.
staging_tags() {
    "$JQ" -r '.tags[]' <<<"$1" |
        while read -r tag; do
            if [[ $tag =~ ^v[0-9]{8}-.*-g([0-9a-f]{7,40})$ && $COMMIT == "${BASH_REMATCH[1]}"* ]]; then
                echo "$tag"
            fi
        done
}

deadline=$((SECONDS + STAGING_WAIT))
while true; do
    # A registry error fails here, instead of passing as a missing image.
    tags=$(registry_get security-profiles-operator/tags/list)
    mapfile -t TAGS < <(staging_tags "$tags")
    if [[ ${#TAGS[@]} -gt 0 ]]; then
        break
    fi
    if [[ $SECONDS -ge $deadline ]]; then
        echo "::error::No staging image of $COMMIT after ${STAGING_WAIT}s, check its post-security-profiles-operator-push-image job"
        exit 1
    fi
    echo "Waiting for the staging image of $COMMIT"
    sleep 60
done

# Shows the manifest and the configuration of an image, to tell which layer or
# which field differs.
show() {
    local manifest="$1" blobs="$2"

    "$JQ" . <<<"$manifest"
    "$blobs" "$("$JQ" -r .config.digest <<<"$manifest")" | "$JQ" .
}

layout_blob() {
    cat "$LAYOUT/blobs/sha256/${1#sha256:}"
}

# shellcheck disable=SC2329 # called by show
staging_blob() {
    registry_get "$REPO/blobs/$1"
}

failed=0
for tag in "${TAGS[@]}"; do
    while read -r ref; do
        REPO="${ref%@*}"
        REPO="${REPO##*/}"
        LAYOUT="$BUILD_DIR/images/${REPO##*-}"
        want="${ref#*@}"
        got="sha256:$(registry_get "$REPO/manifests/$tag" | sha256sum | cut -d' ' -f1)"
        if [[ $got == "$want" ]]; then
            echo "$REPO:$tag is $got, the same as the image built here"
            continue
        fi

        echo "::error::$REPO:$tag is $got, but the image built here is $want"
        echo "Staging image:"
        show "$(registry_get "$REPO/manifests/$tag")" staging_blob
        echo "Image built here:"
        show "$(layout_blob "$want")" layout_blob
        failed=1
    done < <(cat "$BUILD_DIR/image-digests" "$BUILD_DIR/metadata-image-digests")
done

exit "$failed"
