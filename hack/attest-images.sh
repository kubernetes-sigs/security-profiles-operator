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
# document, the build environment and the Scorecard result for the image
# digests listed in build/image-digests, and SLSA provenance for the bundle and
# catalog digests in build/metadata-image-digests. hack/image-cross.sh writes
# both lists. The images are attested in parallel.

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
BUILD_STARTED="$(cat "$BUILD_DIR/build-started")"
export BUILD_STARTED

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
  local ref="$1"

  prefixed "$(image_name "$ref")" "$HACK_DIR/attest-provenance.sh" "$ref"
  prefixed "$(image_name "$ref")" "$HACK_DIR/attest-sbom.sh" "$ref"
  prefixed "$(image_name "$ref")" "$HACK_DIR/attest-vulns.sh" "$ref"
  prefixed "$(image_name "$ref")" "$HACK_DIR/attest-build-env.sh" "$ref"
}

attest_provenance() {
  prefixed "$(image_name "$1")" "$HACK_DIR/attest-provenance.sh" "$1"
}

parallel_each attest_image "${IMAGES[@]}"
# The Scorecard result is the same for all images, so it is fetched once.
"$HACK_DIR/attest-scorecard.sh" "${IMAGES[@]}"
parallel_each attest_provenance "${METADATA_IMAGES[@]}"
