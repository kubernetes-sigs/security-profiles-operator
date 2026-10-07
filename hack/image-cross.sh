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
# the bundle and catalog builds rely on BuildKit
export DOCKER_BUILDKIT=1

# The per-arch images are reproducible: a commit gives the same image digests
# on Cloud Build as in the image-reproducible workflow, which runs this script
# with PUSH=false. That needs the same BuildKit everywhere, so the images are
# built in a container of this pinned BuildKit image instead of by the docker
# daemon. Bump the version and the digest together.
BUILDKIT_VERSION=v0.33.1
BUILDKIT_DIGEST=sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea

# PUSH=false only builds the per-arch images, the bundle and the catalog into
# the OCI layouts build/images/<arch|bundle|catalog> and writes their digests
# to build/image-digests and build/metadata-image-digests. It pushes and signs
# nothing and builds no manifest list.
PUSH=${PUSH:-true}

# PUSH=false renders the catalog from the bundle in a throwaway registry on
# this port, see build_catalog.
LOCAL_REGISTRY_PORT=${LOCAL_REGISTRY_PORT:-5001}

REGISTRY=us-central1-docker.pkg.dev/k8s-staging-images/sp-operator
IMAGE=$REGISTRY/security-profiles-operator
TAG=${TAG:-$(git describe --tags --always --dirty)}

# TODO: reenable s390x when the nix toolchain is fixed
ARCHES=(amd64 arm64 ppc64le)
#ARCHES=(amd64 arm64 ppc64le s390x)
VERSION=v$(cat VERSION)
TAGS=("$TAG" "$VERSION" latest)

# The OCI image annotations. The creation time is the commit time, so that
# the same commit gives the same labels. BuildKit uses SOURCE_DATE_EPOCH for
# the creation time of the image configuration and its history and clamps the
# file times in the layers to it, the native SBOM records it as its creation
# time.
REVISION=$(git rev-parse HEAD)
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
CREATED=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

# The provenance records when the build started and the image the binaries
# are built in, which is pinned to that digest for the build.
mkdir -p build
date -u +%Y-%m-%dT%H:%M:%SZ > build/build-started
BUILD_IMAGE=$(resolve_digest "$(sed -n 's/^ARG BUILD_IMAGE=//p' Dockerfile)")
echo "$BUILD_IMAGE" > build/build-image
# The BuildKit image is part of the provenance of the per-arch images too.
echo "docker.io/moby/buildkit@$BUILDKIT_DIGEST" > build/buildkit-image

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

# Downloaded once, the parallel builds use it.
JQ=$(jq_bin)

# A new builder for every run, so that nothing of an earlier build is reused,
# with a name of its own, so that runs on the same docker daemon don't remove
# each other's builder. It is removed on exit, also when creating it fails
# halfway. The buildx client differs between Cloud Build and GitHub Actions,
# its version is logged to tell them apart when the digests differ.
BUILDER=spo-image-cross-$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
docker buildx version
LOCAL_REGISTRY_PID=
trap 'docker buildx rm "$BUILDER" || true; [[ -z "$LOCAL_REGISTRY_PID" ]] || kill "$LOCAL_REGISTRY_PID" || true' EXIT
docker buildx create \
    --name "$BUILDER" \
    --driver docker-container \
    --driver-opt "image=moby/buildkit:$BUILDKIT_VERSION@$BUILDKIT_DIGEST" \
    --bootstrap

# The exporter options of the per-arch images, the same for the OCI layout and
# the registry: Docker media types like before, gzip compressed by the pinned
# BuildKit and the file times clamped to SOURCE_DATE_EPOCH.
EXPORT_OPTS=oci-mediatypes=false,compression=gzip,force-compression=true,rewrite-timestamp=true

build_arch() {
    local arch="$1" layout="build/images/$1" digest manifest config image_arch pushed
    local outputs=(--output "type=oci,dest=$layout,tar=false,$EXPORT_OPTS")

    if [[ $PUSH == "true" ]]; then
        outputs+=(--output "type=image,\"name=$IMAGE-$arch:$TAG,$IMAGE-$arch:$VERSION,$IMAGE-$arch:latest\",push=true,$EXPORT_OPTS")
    fi

    rm -rf "$layout"
    # No provenance or SBOM attestations of BuildKit: they would turn the
    # per-arch image into an index, the attestations come from
    # hack/attest-images.sh.
    docker buildx build \
        --builder "$BUILDER" \
        --platform "linux/$arch" \
        --provenance=false \
        --sbom=false \
        --build-arg version="$VERSION" \
        --build-arg revision="$REVISION" \
        --build-arg created="$CREATED" \
        --build-arg BUILD_IMAGE="$BUILD_IMAGE" \
        --build-arg target="spo-$arch" \
        --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        "${outputs[@]}" \
        .

    # The layout holds exactly the one image.
    digest=$("$JQ" -er '[.manifests[].digest] | unique | if length == 1 then .[0] else error("expected one image") end' "$layout/index.json")
    manifest="$layout/blobs/sha256/${digest#sha256:}"
    config="$layout/blobs/sha256/$("$JQ" -er '.config.digest | ltrimstr("sha256:")' "$manifest")"
    image_arch=$("$JQ" -er .architecture "$config")
    if [[ $image_arch != "$arch" ]]; then
        echo "Image $IMAGE-$arch has architecture $image_arch, expected $arch"
        return 1
    fi

    # The pushed image has to be the one in the OCI layout, whose digest the
    # image-reproducible workflow compares.
    if [[ $PUSH == "true" ]]; then
        pushed=$(resolve_digest "$IMAGE-$arch:$TAG")
        if [[ ${pushed#*@} != "$digest" ]]; then
            echo "Pushed $pushed, but the OCI layout has $digest"
            return 1
        fi
    fi

    echo "$digest" > "$layout.digest"
}

build() {
    prefixed "$1" build_arch "$1"
}

# The nix builds of the architectures are independent, BuildKit shares the
# common build stage between them.
parallel_each build "${ARCHES[@]}"

# The attestation step attests the per-arch images by digest, in their own
# repositories and in the one of the manifest list (see hack/attest-images.sh)
: > build/image-digests
for ARCH in "${ARCHES[@]}"; do
    echo "$IMAGE-$ARCH@$(cat "build/images/$ARCH.digest")" >> build/image-digests
done
cat build/image-digests

# The bundle and the catalog are reproducible like the per-arch images, built
# by the pinned BuildKit with the same exporter options and the commit time,
# so that the image-reproducible workflow builds the same digests, see
# doc/release.md#bundle-and-catalog. Both are linux/amd64 images, like the
# ones the docker daemon built before.
BUNDLE_IMG_BASE=$IMAGE-bundle
CATALOG_IMG_BASE=$IMAGE-catalog

build_metadata() {
    local name="$1" dockerfile="$2" context="$3" layout="build/images/$1" repo="$IMAGE-$1" digest pushed tag names=''
    local outputs=(--output "type=oci,dest=$layout,tar=false,$EXPORT_OPTS")
    shift 3

    if [[ $PUSH == "true" ]]; then
        for tag in "${TAGS[@]}"; do
            names+="${names:+,}$repo:$tag"
        done
        outputs+=(--output "type=image,\"name=$names\",push=true,$EXPORT_OPTS")
    fi

    rm -rf "$layout"
    docker buildx build \
        --builder "$BUILDER" \
        --platform linux/amd64 \
        --provenance=false \
        --sbom=false \
        --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
        "$@" \
        -f "$dockerfile" \
        "${outputs[@]}" \
        "$context"

    digest=$("$JQ" -er '[.manifests[].digest] | unique | if length == 1 then .[0] else error("expected one image") end' "$layout/index.json")
    if [[ $PUSH == "true" ]]; then
        pushed=$(resolve_digest "$repo:$TAG")
        if [[ ${pushed#*@} != "$digest" ]]; then
            echo "Pushed $pushed, but the OCI layout has $digest"
            return 1
        fi
    fi
    echo "$digest" > "$layout.digest"
}

# The catalog is rendered from the bundle by digest. Released catalogs
# reference the bundle in the production registry it gets promoted to,
# because staging images are not kept. Development catalogs keep the staging
# bundle, which is never promoted. Without PUSH, the bundle is rendered from a
# throwaway registry and its references are rewritten to the staging bundle,
# which gives the same catalog, since opm renders the bundle content and only
# names the repository.
build_catalog() {
    local digest bundle catalog_repo='' local_bundle image attempt crane
    local -a catalog_args=()

    digest=$(cat build/images/bundle.digest)
    bundle="$BUNDLE_IMG_BASE@$digest"
    if [[ "$VERSION" != *-dev ]]; then
        catalog_repo=registry.k8s.io/security-profiles-operator/security-profiles-operator-bundle
    fi

    if [[ $PUSH != "true" ]]; then
        crane=$(crane_bin) || return 1
        "$crane" registry serve --address "127.0.0.1:$LOCAL_REGISTRY_PORT" &
        LOCAL_REGISTRY_PID=$!
        local_bundle="127.0.0.1:$LOCAL_REGISTRY_PORT/${BUNDLE_IMG_BASE##*/}"
        # The registry takes a moment to listen.
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            "$crane" push --insecure build/images/bundle "$local_bundle:$TAG" && break
            if [[ $attempt -eq 10 ]] || ! kill -0 "$LOCAL_REGISTRY_PID" 2>/dev/null; then
                echo "Unable to push the bundle to the registry on port $LOCAL_REGISTRY_PORT"
                return 1
            fi
            sleep 1
        done
        bundle="$local_bundle@$digest"
        catalog_repo=${catalog_repo:-$BUNDLE_IMG_BASE}
        catalog_args+=(OPM_EXTRA_ARGS=--use-http)
    fi
    if [[ -n "$catalog_repo" ]]; then
        catalog_args+=(CATALOG_BUNDLE_REPO="$catalog_repo")
    fi
    make catalog-context BUNDLE_IMGS="$bundle" "${catalog_args[@]}"

    # The base image of the catalog by digest, like in its provenance, see
    # hack/attest-images.sh.
    image=$(opm_image) || return 1
    build_metadata catalog catalog.Dockerfile build/catalog \
        --build-arg OPM_IMAGE="$image"
}

# The bundle files with fixed modes, like the catalog, see bundle-context in
# the Makefile.
make bundle-context
build_metadata bundle bundle.Dockerfile build/bundle
build_catalog

# The attestation step attests the bundle and the catalog by digest, see
# hack/attest-images.sh.
printf '%s\n' \
    "$BUNDLE_IMG_BASE@$(cat build/images/bundle.digest)" \
    "$CATALOG_IMG_BASE@$(cat build/images/catalog.digest)" > build/metadata-image-digests
cat build/metadata-image-digests

if [[ $PUSH != "true" ]]; then
    exit 0
fi

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

# The manifest list only carries the signature, hack/verify-attestations.sh
# checks it together with the digests the later build steps record.
INDEX_DIGEST_IMG=$(resolve_digest "$IMAGE:$TAG")
: > build/artifact-digests
record_digest index "$INDEX_DIGEST_IMG"

# Sign every pushed image once by digest, if SIGN=true
SIGN_REFS=("$IMAGE:$TAG" "$BUNDLE_IMG_BASE:$TAG" "$CATALOG_IMG_BASE:$TAG")
for ARCH in "${ARCHES[@]}"; do
    SIGN_REFS+=("$IMAGE-$ARCH:$TAG")
done
# Container runtimes pull the per-arch images by digest from the repository of
# the manifest list, so they are signed there too.
while read -r ARCH_DIGEST_IMG; do
    SIGN_REFS+=("$IMAGE@${ARCH_DIGEST_IMG#*@}")
done < build/image-digests
"$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "${SIGN_REFS[@]}"
