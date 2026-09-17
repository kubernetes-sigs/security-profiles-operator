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

# Attests the build environment (https://in-toto.io/attestation/build-env/v1)
# of each given image digest. The values come from the Go build information of
# the binaries in the image and from the build image definitions. No hermetic
# or reproducible build is claimed.

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

BINARIES=(security-profiles-operator spoc)

if ! signing_enabled; then
  echo "Signing disabled, not attesting build environments: $*"
  exit 0
fi

for ref in "$@"; do
  require_digest "$ref"
done

if [[ -s "$BUILD_DIR/build-image" ]]; then
  BUILD_IMAGE="$(cat "$BUILD_DIR/build-image")"
else
  BUILD_IMAGE=$(sed -n 's/^ARG BUILD_IMAGE=//p' Dockerfile)
fi
NIX_VERSION=$(sed -n 's/^ARG NIX_VERSION=//p' Dockerfile.build-image)

mkdir -p "$BUILD_DIR/attestations"

for ref in "$@"; do
  name="$(image_name "$ref")"
  binaries="$(extract_binaries "$ref")"
  predicate="$BUILD_DIR/attestations/$name.build-env.json"

  for binary in "${BINARIES[@]}"; do
    go version -m -json "$binaries/$binary"
  done | "$(jq_bin)" -s \
    --arg buildImage "$BUILD_IMAGE" \
    --arg nixVersion "$NIX_VERSION" \
    --arg project "${PROJECT_ID:-}" \
    '{
      environment: (
        [
          {name: "BUILD_SYSTEM", value: "cloudbuild"},
          {name: "BUILD_PROJECT", value: $project},
          {name: "BUILD_IMAGE", value: $buildImage},
          {name: "NIX_VERSION", value: $nixVersion}
        ]
        + [.[] | (.Path | split("/") | last) as $binary
            | {name: "\($binary).GO_VERSION", value: .GoVersion},
              (.Settings[] | {name: "\($binary).\(.Key)", value: .Value})]
      )
    }' >"$predicate"

  attest "$ref" https://in-toto.io/attestation/build-env/v1 "$predicate"
done
