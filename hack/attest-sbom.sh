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
# The images are built from scratch and bom cannot read the module information
# of Go binaries yet (kubernetes-sigs/bom#347), so the SBOM lists the image
# together with the Go modules of this repository. Runs from the repository
# root and needs go.

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

# bom reads the module licenses from the module cache, with the vendor
# directory it would clone every dependency repository instead. The read-only
# module mode never writes go.mod or go.sum, which keeps parallel runs apart.
go mod download

mkdir -p "$BUILD_DIR/attestations"

for ref in "$@"; do
  name="$(image_name "$ref")"
  sbom="$BUILD_DIR/attestations/$name.spdx.json"

  # bom keeps its license data in fixed paths below the temporary directory,
  # so parallel runs need their own.
  tmp="$BUILD_DIR/tmp/$name"
  mkdir -p "$tmp"

  echo "Generating the SBOM for $ref"
  # The ignore patterns keep the repository files out of the SBOM, go.mod and
  # go.sum stay because bom needs at least one file in the scanned directory.
  TMPDIR="$(realpath "$tmp")" GOFLAGS=-mod=readonly "$(bom_bin)" generate \
    --format json \
    -l Apache-2.0 \
    --name "$name" \
    -d . \
    --ignore '*' \
    --ignore '!go.mod' \
    --ignore '!go.sum' \
    -i "$ref" \
    -o "$sbom"

  attest "$ref" https://spdx.dev/Document "$sbom"
done
