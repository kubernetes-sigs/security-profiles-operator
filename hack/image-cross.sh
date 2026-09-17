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

set -euox pipefail

# just in case we're not using docker 20.10
export DOCKER_CLI_EXPERIMENTAL=enabled
# the Dockerfile relies on BUILDPLATFORM, which only BuildKit provides
export DOCKER_BUILDKIT=1

REGISTRY=us-central1-docker.pkg.dev/k8s-staging-images/sp-operator
IMAGE=$REGISTRY/security-profiles-operator
TAG=${TAG:-$(git describe --tags --always --dirty)}

# TODO: reenable s390x when the nix toolchain is fixed
ARCHES=(amd64 arm64 ppc64le)
#ARCHES=(amd64 arm64 ppc64le s390x)
VERSION=v$(cat VERSION)
TAGS=("$TAG" "$VERSION" latest)

for ARCH in "${ARCHES[@]}"; do
    docker build \
        --platform "linux/$ARCH" \
        -t "$IMAGE-$ARCH:$TAG" \
        -t "$IMAGE-$ARCH:$VERSION" \
        -t "$IMAGE-$ARCH:latest" \
        --build-arg version="$VERSION" \
        --build-arg target="spo-$ARCH" \
        .

    IMAGE_ARCH=$(docker image inspect --format '{{.Architecture}}' "$IMAGE-$ARCH:$TAG")
    if [[ $IMAGE_ARCH != "$ARCH" ]]; then
        echo "Image $IMAGE-$ARCH:$TAG has architecture $IMAGE_ARCH, expected $ARCH"
        exit 1
    fi

    for T in "${TAGS[@]}"; do
        docker push "$IMAGE-$ARCH:$T"
    done
done

for T in "${TAGS[@]}"; do
    docker manifest create --amend "$IMAGE:$T" \
        "$IMAGE-amd64:$T" \
        "$IMAGE-arm64:$T" \
        "$IMAGE-ppc64le:$T"

    for ARCH in "${ARCHES[@]}"; do
        docker manifest annotate --arch "$ARCH" "$IMAGE:$T" "$IMAGE-$ARCH:$T"
    done

    docker manifest push --purge "$IMAGE:$T"
done

# Build and push the bundle and catalog image
BUNDLE_IMG_BASE=$IMAGE-bundle
CATALOG_IMG_BASE=$IMAGE-catalog

export BUNDLE_IMG=$BUNDLE_IMG_BASE:$VERSION
export CATALOG_IMG=$CATALOG_IMG_BASE:$VERSION

make bundle-build bundle-push CONTAINER_RUNTIME=docker

# The catalog is rendered from the pushed staging bundle by digest. Released
# catalogs reference the bundle in the production registry it gets promoted
# to, because staging images are not kept. Development catalogs keep the
# staging bundle, which is never promoted.
BUNDLE_DIGEST_IMG=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$BUNDLE_IMG" |
    grep -F "$BUNDLE_IMG_BASE@sha256:" | head -1)
if [[ -z "$BUNDLE_DIGEST_IMG" ]]; then
    echo "Unable to resolve the digest of $BUNDLE_IMG"
    exit 1
fi

CATALOG_ARGS=(BUNDLE_IMGS="$BUNDLE_DIGEST_IMG")
if [[ "$VERSION" != *-dev ]]; then
    CATALOG_ARGS+=(CATALOG_BUNDLE_REPO=registry.k8s.io/security-profiles-operator/security-profiles-operator-bundle)
fi

make catalog-build catalog-push CONTAINER_RUNTIME=docker "${CATALOG_ARGS[@]}"

# Ensure all tags are up to date
IMAGES=("$BUNDLE_IMG_BASE" "$CATALOG_IMG_BASE")
for I in "${IMAGES[@]}"; do
    for T in "${TAGS[@]}"; do
        docker tag "$I:$VERSION" "$I:$T"
        docker push "$I:$T"
    done
done

# Sign every pushed image once by digest, if SIGN=true
SIGN_REFS=("$IMAGE:$TAG" "$BUNDLE_IMG_BASE:$TAG" "$CATALOG_IMG_BASE:$TAG")
for ARCH in "${ARCHES[@]}"; do
    SIGN_REFS+=("$IMAGE-$ARCH:$TAG")
done
"$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "${SIGN_REFS[@]}"
