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

# Attests SLSA provenance and an SPDX 3 SBOM for an OCI artifact the build
# pushed, a security profile or the -dev helm chart, or a profile it found
# already published. FILE is the content of its layer: the SBOM lists a profile as file
# by the NAME it has in the artifact, which defaults to the name of FILE, and a
# chart archive with the files it holds. Callers make sure that the published content is the
# one of FILE.
#
# An attestation is only added when the artifact has none of the predicate
# type yet that the build identity signed (SIGNER_IDENTITY_REGEXP and
# SIGNER_OIDC_ISSUER_REGEXP, like hack/sign-published.sh), and for the
# provenance one that names the builder ID and the source the image promoter
# expects. So artifacts that were published before the build attested them
# get their attestations from the next build, and later builds add no
# duplicates. Without the regexps every attestation is added again.
#
# The digest is recorded for hack/verify-attestations.sh. Like
# hack/attest-provenance.sh, this does nothing outside of Cloud Build, and
# PROVENANCE_DEPENDENCIES is passed on to it.
#
# Usage: hack/attest-artifact.sh REF FILE [NAME]

set -euo pipefail

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=hack/lib/common.sh
source "$HACK_DIR/lib/common.sh"

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 REF FILE [NAME]" >&2
  exit 1
fi

FILE="$2"
NAME="${3:-$(basename "$FILE")}"

if ! signing_enabled; then
  echo "Signing disabled, not attesting $1"
  exit 0
fi

if [[ -z "${BUILD_ID:-}" ]]; then
  echo "Not running in Cloud Build, not attesting $1"
  exit 0
fi

REF="$(resolve_digest "$1")"
record_digest artifact "$REF"

# Whether the artifact already has an attestation of the type by the build
# identity, which the filter of the predicate type accepts.
attested() {
  local type="$1" check="$2" statements

  if ! signer_args >/dev/null 2>&1; then
    echo "No signer identity configured, attesting $type for $REF without checking for an existing one"
    return 1
  fi
  # A failed lookup fails, rather than adding a duplicate.
  statements="$(attestations "$REF" "$type")" || exit 1
  if [[ -z "$statements" ]] || ! "$check" <<<"$statements" >/dev/null; then
    echo "No $type attestation of the build on $REF, attesting it"
    return 1
  fi
  echo "$REF already has a $type attestation of the build"
}

if ! attested "$SLSA_PROVENANCE" valid_provenance; then
  "$HACK_DIR/attest-provenance.sh" "$REF"
fi

if ! attested "$SPDX_DOCUMENT" cat; then
  sbom="$(artifact_sbom "$BUILD_DIR/attestations/$(image_name "$REF")-${REF##*:}" "${1##*/}" "$FILE" "$NAME")"
  attest "$REF" "$SPDX_DOCUMENT" "$sbom"
fi
