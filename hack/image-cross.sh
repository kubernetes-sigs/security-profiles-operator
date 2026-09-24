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

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

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

# The provenance records when the build started and the image the binaries
# are built in, which is pinned to that digest for the build.
mkdir -p build
date -u +%Y-%m-%dT%H:%M:%SZ > build/build-started
BUILD_IMAGE=$(resolve_digest "$(sed -n 's/^ARG BUILD_IMAGE=//p' Dockerfile)")
echo "$BUILD_IMAGE" > build/build-image

# The build image is the toolchain that compiles the released binaries, so
# verify it is the one this project published before building against it: the
# build workflow signs it on pushes to main.
if [[ "${VERIFY_BUILD_IMAGE:-true}" == "true" ]]; then
    : "${BUILD_IMAGE_IDENTITY_REGEXP:=^https://github\.com/kubernetes-sigs/security-profiles-operator/\.github/workflows/build\.yml@refs/heads/main$}"
    : "${BUILD_IMAGE_OIDC_ISSUER_REGEXP:=^https://token\.actions\.githubusercontent\.com$}"

    "$(cosign_bin)" verify \
        --certificate-identity-regexp "$BUILD_IMAGE_IDENTITY_REGEXP" \
        --certificate-oidc-issuer-regexp "$BUILD_IMAGE_OIDC_ISSUER_REGEXP" \
        "$BUILD_IMAGE" >/dev/null
fi

build_arch() {
    local arch="$1" image_arch

    docker build \
        --platform "linux/$arch" \
        -t "$IMAGE-$arch:$TAG" \
        -t "$IMAGE-$arch:$VERSION" \
        -t "$IMAGE-$arch:latest" \
        --build-arg version="$VERSION" \
        --build-arg BUILD_IMAGE="$BUILD_IMAGE" \
        --build-arg target="spo-$arch" \
        .

    image_arch=$(docker image inspect --format '{{.Architecture}}' "$IMAGE-$arch:$TAG")
    if [[ $image_arch != "$arch" ]]; then
        echo "Image $IMAGE-$arch:$TAG has architecture $image_arch, expected $arch"
        return 1
    fi
}

push_arch() {
    local arch="$1" t

    for t in "${TAGS[@]}"; do
        docker push "$IMAGE-$arch:$t"
    done
}

build() {
    prefixed "$1" build_arch "$1"
}

push() {
    prefixed "$1" push_arch "$1"
}

# The nix builds of the architectures are independent, BuildKit shares the
# common build stage between them.
parallel_each build "${ARCHES[@]}"
parallel_each push "${ARCHES[@]}"

# The attestation step attests the per-arch images by digest
: > build/image-digests
for ARCH in "${ARCHES[@]}"; do
    ARCH_DIGEST_IMG=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE-$ARCH:$TAG" |
        grep -F "$IMAGE-$ARCH@sha256:" | head -1)
    if [[ -z "$ARCH_DIGEST_IMG" ]]; then
        echo "Unable to resolve the digest of $IMAGE-$ARCH:$TAG"
        exit 1
    fi
    echo "$ARCH_DIGEST_IMG" >> build/image-digests
done

push_manifest() {
    local tag="$1" arch

    # Build the member list from ARCHES so that re-enabling an architecture
    # cannot silently produce a manifest that is missing it.
    local members=()
    for arch in "${ARCHES[@]}"; do
        members+=("$IMAGE-$arch:$tag")
    done

    docker manifest create --amend "$IMAGE:$tag" "${members[@]}"

    for arch in "${ARCHES[@]}"; do
        docker manifest annotate --arch "$arch" "$IMAGE:$tag" "$IMAGE-$arch:$tag"
    done

    docker manifest push --purge "$IMAGE:$tag"
}

parallel_each push_manifest "${TAGS[@]}"

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

# The bundle and catalog only get provenance, they contain no software
CATALOG_DIGEST_IMG=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$CATALOG_IMG" |
    grep -F "$CATALOG_IMG_BASE@sha256:" | head -1)
if [[ -z "$CATALOG_DIGEST_IMG" ]]; then
    echo "Unable to resolve the digest of $CATALOG_IMG"
    exit 1
fi
printf '%s\n' "$BUNDLE_DIGEST_IMG" "$CATALOG_DIGEST_IMG" > build/metadata-image-digests

# Sign every pushed image once by digest, if SIGN=true
SIGN_REFS=("$IMAGE:$TAG" "$BUNDLE_IMG_BASE:$TAG" "$CATALOG_IMG_BASE:$TAG")
for ARCH in "${ARCHES[@]}"; do
    SIGN_REFS+=("$IMAGE-$ARCH:$TAG")
done
"$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "${SIGN_REFS[@]}"
