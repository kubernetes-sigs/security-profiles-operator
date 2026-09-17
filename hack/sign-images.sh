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

# Signs the given image references keylessly by digest. The signatures are
# Sigstore bundles attached as OCI referrers. The identity comes from the
# ambient credentials, for example the metadata server in Cloud Build.
# SIGN=false skips signing.

set -euo pipefail

SIGN="${SIGN:-true}"
COSIGN_VERSION=v3.1.3
COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
COSIGN="${COSIGN:-}"

if [[ "$SIGN" != "true" ]]; then
  echo "Signing disabled, not signing: $*"
  exit 0
fi

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 IMAGE:TAG|IMAGE@DIGEST..." >&2
  exit 1
fi

if [[ -z "$COSIGN" ]]; then
  COSIGN="$(mktemp -d)/cosign"
  curl -sSfL --retry 5 --retry-delay 3 -o "$COSIGN" \
    "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64"
  echo "$COSIGN_SHA256  $COSIGN" | sha256sum -c -
  chmod +x "$COSIGN"
fi

# All tags of an image point to the same digest, so signing one reference
# per image is enough. References that already contain a digest, for example
# OCI artifacts like helm charts, are signed as given.
for ref in "$@"; do
  if [[ "$ref" == *@sha256:* ]]; then
    target="$ref"
  else
    digest=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')
    if [[ -z "$digest" ]]; then
      echo "Unable to resolve the digest of $ref" >&2
      exit 1
    fi
    target="${ref%:*}@$digest"
  fi

  echo "Signing $target"
  "$COSIGN" sign --yes \
    --use-signing-config \
    "$target"
done
