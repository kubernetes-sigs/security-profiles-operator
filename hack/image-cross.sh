#!/usr/bin/env bash
# Copyright 2021 The Kubernetes Authors.
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

REGISTRY=gcr.io/k8s-staging-sp-operator
IMAGE=$REGISTRY/security-profiles-operator
TAG=${TAG:-$(git describe --tags --always --dirty)}

ARCHES=(amd64 arm64)
VERSION=v$(cat VERSION)
QEMUVERSION=6.1.0-8
TAGS=("$TAG" "$VERSION" latest)

# Build and push the main image
docker run --rm --privileged \
    multiarch/qemu-user-static:$QEMUVERSION --reset -p yes
docker buildx version
BUILDER=$(docker buildx create --use)

for ARCH in "${ARCHES[@]}"; do
    docker buildx build \
        --pull \
        --load \
        --platform "linux/$ARCH" \
        -t "$IMAGE-$ARCH:$TAG" \
        -t "$IMAGE-$ARCH:$VERSION" \
        -t "$IMAGE-$ARCH:latest" \
        --build-arg version="$VERSION" \
        --build-arg target="nix/default-$ARCH.nix" \
        .
    for T in "${TAGS[@]}"; do
        docker push "$IMAGE-$ARCH:$T"
    done
done

docker buildx rm "$BUILDER"

for T in "${TAGS[@]}"; do
    docker manifest create --amend "$IMAGE:$T" \
        "$IMAGE-amd64:$T" \
        "$IMAGE-arm64:$T"

    for ARCH in "${ARCHES[@]}"; do
        docker manifest annotate --arch "$ARCH" "$IMAGE:$T" "$IMAGE-$ARCH:$T"
    done

    docker manifest push --purge "$IMAGE:$T"
done

# Manually install OPM because of failing symbol relocation of the non-static
# upstream binary build.
# TODO: remove me when switching to a new OPM version, which are nowadays
# correctly statically linked.
OPM_VERSION=1.19.1
OPM_REPO=operator-registry
OPM_DIR=$OPM_REPO-$OPM_VERSION
apk add --no-cache gcc libc-dev
curl -sSfL --retry 5 --retry-delay 3 \
    "https://github.com/operator-framework/$OPM_REPO/archive/refs/tags/v$OPM_VERSION.tar.gz" -o- |
    tar xfz -
make -C $OPM_DIR bin/opm CGO_LDFLAGS=
mkdir -p build
cp $OPM_DIR/bin/opm build/opm

# Build and push the bundle and catalog image
BUNDLE_IMG_BASE=$IMAGE-bundle
CATALOG_IMG_BASE=$IMAGE-catalog

export BUNDLE_IMG=$BUNDLE_IMG_BASE:$VERSION
export CATALOG_IMG=$CATALOG_IMG_BASE:$VERSION

make bundle-build bundle-push catalog-build catalog-push

# Ensure all tags are up to date
IMAGES=("$BUNDLE_IMG_BASE" "$CATALOG_IMG_BASE")
for I in "${IMAGES[@]}"; do
    for T in "${TAGS[@]}"; do
        docker tag "$I:$VERSION" "$I:$T"
        docker push "$I:$T"
    done
done
