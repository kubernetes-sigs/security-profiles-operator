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

# Attests SLSA provenance, the SBOM, the vulnerability scan with its VEX
# document, the build environment and the Scorecard result for the per-arch
# image digests listed in build/image-digests, and SLSA provenance and the
# SBOM for the bundle and catalog digests in build/metadata-image-digests,
# plus the vulnerability scan with its VEX document for the catalog, which
# holds the opm binaries of its base image. hack/image-cross.sh writes both
# lists. Container runtimes pull the per-arch images by digest from the
# repository of their manifest list, where verifiers and the image promoter
# look up attestations, so the per-arch attestations are attached there too.
# The images are attested in parallel.

set -euo pipefail

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=hack/lib/common.sh
source "$HACK_DIR/lib/common.sh"

if ! signing_enabled; then
  echo "Signing disabled, not attesting images"
  exit 0
fi

mapfile -t IMAGES <"$BUILD_DIR/image-digests"
mapfile -t METADATA_IMAGES <"$BUILD_DIR/metadata-image-digests"

# The same digests in the repository of the manifest list, for attest.
ATTEST_ALIASES=""
for ref in "${IMAGES[@]}"; do
  repo="${ref%@*}"
  if [[ ! "$repo" =~ -(amd64|arm64|ppc64le|s390x)$ ]]; then
    echo "$ref is no per-arch image" >&2
    exit 1
  fi
  ATTEST_ALIASES+="$ref ${repo%-*}@${ref#*@}"$'\n'
done
export ATTEST_ALIASES
BUILD_STARTED="$(cat "$BUILD_DIR/build-started")"
export BUILD_STARTED

# The resolved dependencies of the provenance: the binaries of the per-arch
# images are compiled with the build toolchain and the images built by the
# pinned BuildKit image, which decides their digests, from
# build/buildkit-image. The same BuildKit builds the bundle, which holds the
# files of this repository only, and the catalog, which is rendered from the
# bundle by the opm release binary on top of the opm image, see
# catalog-context and catalog-build in the Makefile, so it is a dependency of
# both as well.
TOOLCHAIN_DEPENDENCIES="$(toolchain_dependencies)"
BUILDKIT_DEPENDENCY="$(oci_dependency "$(cat "$BUILD_DIR/buildkit-image")" buildkit)"
# jq programs are single quoted on purpose
# shellcheck disable=SC2016
IMAGE_DEPENDENCIES="$("$(jq_bin)" -cn \
  --argjson toolchain "$TOOLCHAIN_DEPENDENCIES" --argjson buildkit "$BUILDKIT_DEPENDENCY" \
  '$toolchain + [$buildkit]')"
BUNDLE="$(grep -E -- '-bundle@sha256:' "$BUILD_DIR/metadata-image-digests")"
OPM_IMAGE="$(opm_image)"
OPM_VERSION="$(sed -n 's/^OPM_VERSION ?= //p' Makefile)"
if [[ -z "$OPM_VERSION" ]]; then
  echo "Unable to read OPM_VERSION from the Makefile" >&2
  exit 1
fi
CATALOG_DEPENDENCIES="$({
  oci_dependency "$OPM_IMAGE" opm-image &&
    file_dependency opm "$BUILD_DIR/opm" \
      "https://github.com/operator-framework/operator-registry/releases/download/$OPM_VERSION/linux-amd64-opm" &&
    oci_dependency "$BUNDLE" bundle &&
    echo "$BUILDKIT_DEPENDENCY"
} | "$(jq_bin)" -cs .)"
# shellcheck disable=SC2016
BUNDLE_DEPENDENCIES="$("$(jq_bin)" -cn --argjson buildkit "$BUILDKIT_DEPENDENCY" '[$buildkit]')"

# Install the tools once, before the parallel runs.
cosign_bin >/dev/null
bom_bin >/dev/null
jq_bin >/dev/null
govulncheck_bin >/dev/null
crane_bin >/dev/null

# This step has no credential helper for the registry.
if [[ -n "${BUILD_ID:-}" ]]; then
  registry_login "${IMAGES[0]%%/*}"
fi

attest_image() {
  local ref="$1" name

  name="$(image_name "$ref")"
  PROVENANCE_DEPENDENCIES="$IMAGE_DEPENDENCIES" \
    prefixed "$name" "$HACK_DIR/attest-provenance.sh" "$ref"
  prefixed "$name" "$HACK_DIR/attest-sbom.sh" "$ref"
  prefixed "$name" "$HACK_DIR/attest-vulns.sh" "$ref"
  prefixed "$name" "$HACK_DIR/attest-build-env.sh" "$ref"
}

attest_metadata_image() {
  local ref="$1" name

  name="$(image_name "$ref")"
  case "$name" in
  *-bundle)
    PROVENANCE_DEPENDENCIES="$BUNDLE_DEPENDENCIES" \
      prefixed "$name" "$HACK_DIR/attest-provenance.sh" "$ref"
    prefixed "$name" "$HACK_DIR/attest-sbom.sh" "$ref"
    ;;
  *-catalog)
    PROVENANCE_DEPENDENCIES="$CATALOG_DEPENDENCIES" \
      prefixed "$name" "$HACK_DIR/attest-provenance.sh" "$ref"
    prefixed "$name" "$HACK_DIR/attest-sbom.sh" "$ref"
    prefixed "$name" "$HACK_DIR/attest-vulns.sh" "$ref"
    ;;
  *)
    echo "$ref is neither the bundle nor the catalog" >&2
    return 1
    ;;
  esac
}

parallel_each attest_image "${IMAGES[@]}"
# The Scorecard result is the same for all images, so it is fetched once.
"$HACK_DIR/attest-scorecard.sh" "${IMAGES[@]}"
parallel_each attest_metadata_image "${METADATA_IMAGES[@]}"
