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

# Attests an SPDX SBOM (https://spdx.dev/Document) for each given image digest.
# bom extracts the Go binary dependencies directly from the image, so the SBOM
# includes actual build-time module versions.

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if ! signing_enabled; then
  echo "Signing disabled, not attesting SBOMs: $*"
  exit 0
fi

for ref in "$@"; do
  require_digest "$ref"
done

mkdir -p "$BUILD_DIR/attestations"

for ref in "$@"; do
  name="$(image_name "$ref")"
  sbom="$BUILD_DIR/attestations/$name.spdx.json"

  echo "Generating the SBOM for $ref"
  "$(bom_bin)" generate \
    --format spdx3-json \
    --name "$name" \
    -i "$ref" \
    -o "$sbom"

  attest "$ref" https://spdx.dev/Document "$sbom"
done
