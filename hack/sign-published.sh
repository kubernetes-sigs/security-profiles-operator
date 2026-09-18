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

# Signs already published artifacts that have no valid signature yet, for
# example versions that were published before the build could sign. Artifacts
# signed by SIGNER_IDENTITY_REGEXP are left alone. The two regexps are never
# defaulted to ".*": that would mean an attacker's signature counts as "already
# signed" and suppresses re-signing. When they are unset, as on a manual run,
# nothing is treated as already signed and every ref is signed again, which is
# harmless because a second signature is simply added.
# SIGN=false skips signing.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
SPOC="${SPOC:-$BUILD_DIR/spoc}"
SIGN="${SIGN:-true}"
SIGNER_IDENTITY_REGEXP="${SIGNER_IDENTITY_REGEXP:-}"
SIGNER_OIDC_ISSUER_REGEXP="${SIGNER_OIDC_ISSUER_REGEXP:-}"

if [[ "$SIGN" != "true" ]]; then
  exit 0
fi

for ref in "$@"; do
  if [[ -n "$SIGNER_IDENTITY_REGEXP" && -n "$SIGNER_OIDC_ISSUER_REGEXP" ]]; then
    if "$SPOC" pull -o /dev/null \
        --allowed-identity-regexp "$SIGNER_IDENTITY_REGEXP" \
        --allowed-oidc-issuer-regexp "$SIGNER_OIDC_ISSUER_REGEXP" \
        "$ref" >/dev/null 2>&1; then
      continue
    fi
  else
    echo "No signer identity configured, signing $ref without checking for an existing signature"
  fi

  echo "No valid signature on $ref, signing it"
  "$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "$ref"
done
