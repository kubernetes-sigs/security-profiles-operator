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

# Attests the latest OpenSSF Scorecard result of this repository
# (https://scorecard.dev/result/v0.1, the provisional predicate type that
# verifiers like nri-supply-chain recognize) for each given image digest. The
# result comes from the public Scorecard API, it describes the repository at
# the commit Scorecard scanned last, which may be older than the built commit.
# An unavailable API skips the attestation with a warning.

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

SCORECARD_API="${SCORECARD_API:-https://api.securityscorecards.dev/projects/${REPOSITORY_URL#https://}}"

if ! signing_enabled; then
  echo "Signing disabled, not attesting Scorecard results: $*"
  exit 0
fi

for ref in "$@"; do
  require_digest "$ref"
done

mkdir -p "$BUILD_DIR/attestations"
result="$BUILD_DIR/attestations/scorecard.json"

if ! curl -sSf --retry 5 --retry-delay 3 -o "$result" "$SCORECARD_API"; then
  echo "WARNING: unable to fetch the Scorecard result from $SCORECARD_API, not attesting it" >&2
  exit 0
fi

if ! "$(jq_bin)" -e '
    (.repo.name | type == "string")
    and (.scorecard.version | type == "string")
    and (.score | type == "number")
    and ((.checks // []) | length > 0)' "$result" >/dev/null; then
  echo "WARNING: unexpected Scorecard result from $SCORECARD_API, not attesting it" >&2
  exit 0
fi

for ref in "$@"; do
  attest "$ref" https://scorecard.dev/result/v0.1 "$result"
done
