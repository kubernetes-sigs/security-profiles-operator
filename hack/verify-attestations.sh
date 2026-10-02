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

# Verifies, as the last step of the staging build, that every digest the build
# pushed, or found published with the content of the repository, carries the
# signature and the attestations the image promoter checks and the build
# attaches, so that a failed attest step or a missing attestation fails the
# build rather than the promotion. Every digest needs a cosign signature
# (https://sigstore.dev/cosign/sign/v1) of the build identity, and by kind:
#
# - image: a per-arch operator image of build/image-digests, in its own
#   repository and in the one of the manifest list, where the image promoter
#   checks the platform images: SLSA provenance, the SPDX SBOMs of the image
#   and of its native libraries, the vulnerability scan, the OpenVEX document
#   when the scan found vulnerabilities, and the build environment
# - bundle, of build/metadata-image-digests: SLSA provenance and the SBOM
# - catalog, of build/metadata-image-digests: SLSA provenance, the SBOM, the
#   vulnerability scan and the OpenVEX document when the scan found
#   vulnerabilities
# - artifact, a profile or the chart of build/artifact-digests, see
#   hack/attest-artifact.sh: SLSA provenance and the SBOM. A published profile
#   or chart with another content is not recorded, see attest_profile in
#   hack/lib/common.sh.
# - index, the manifest list of build/artifact-digests: only the signature
#
# The SLSA provenance has to be about the digest, name the builder ID of the
# build and this repository as source, which is what the provenance policy of
# the image promoter checks. The Scorecard result is not required, the build
# skips it when the Scorecard API is unavailable.
#
# The build identity is SIGNER_IDENTITY with SIGNER_OIDC_ISSUER, the builder ID
# comes from PROJECT_ID and SERVICE_ACCOUNT_EMAIL. The script only reads from
# the registry, KIND=REF arguments verify other digests than the ones of the
# build, for example:
#
#   PROJECT_ID=k8s-staging-images \
#   SERVICE_ACCOUNT_EMAIL=sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
#   SIGNER_IDENTITY=sp-operator-sa@k8s-staging-images.iam.gserviceaccount.com \
#   SIGNER_OIDC_ISSUER=https://accounts.google.com \
#   hack/verify-attestations.sh \
#   artifact=us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/base/runc@sha256:...

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if ! signing_enabled; then
  echo "Signing disabled, not verifying attestations"
  exit 0
fi

: "${SIGNER_IDENTITY:?SIGNER_IDENTITY must be set}"
: "${SIGNER_OIDC_ISSUER:?SIGNER_OIDC_ISSUER must be set}"
builder_id >/dev/null

DIGESTS=()
if [[ $# -gt 0 ]]; then
  DIGESTS=("$@")
else
  while read -r ref; do
    DIGESTS+=("image=$ref")
  done <"$BUILD_DIR/image-digests"
  while read -r ref; do
    case "$(image_name "$ref")" in
    *-bundle) DIGESTS+=("bundle=$ref") ;;
    *-catalog) DIGESTS+=("catalog=$ref") ;;
    *) DIGESTS+=("unknown=$ref") ;;
    esac
  done <"$BUILD_DIR/metadata-image-digests"
  while read -r kind ref; do
    DIGESTS+=("$kind=$ref")
  done <"$BUILD_DIR/artifact-digests"
fi

# The platform images are verified in the repository of their manifest list
# too. Profiles that are published under several tags are verified once.
EXPANDED=()
for digest in "${DIGESTS[@]}"; do
  kind="${digest%%=*}" ref="${digest#*=}"
  case "$kind" in
  image | bundle | catalog | artifact | index) ;;
  *)
    echo "Unknown kind of digest $digest" >&2
    exit 1
    ;;
  esac
  require_digest "$ref"

  EXPANDED+=("$digest")
  if [[ "$kind" == image ]]; then
    repo="${ref%@*}"
    EXPANDED+=("image=${repo%-*}@${ref#*@}")
  fi
done
mapfile -t DIGESTS < <(printf '%s\n' "${EXPANDED[@]}" | sort -u)

# Install the tools once, before the parallel runs.
cosign_bin >/dev/null
jq_bin >/dev/null

# This step has no credential helper for the registry.
if [[ -n "${BUILD_ID:-}" ]]; then
  registry_login "${STAGING_REGISTRY%%/*}"
fi

# Runs a check and prints its result, with what is missing when it fails.
check() {
  local what="$1" out
  shift

  if out="$("$@" 2>&1)"; then
    echo "ok: $what"
  else
    echo "FAILED: $what${out:+ ($(tr '\n' ';' <<<"$out" | sed 's/;$//; s/;/; /g'))}"
    return 1
  fi
}

# Prints the statements of the predicate type about the digest by the build
# identity, see attestations, and fails with the message on stderr when there
# are none.
lookup() {
  local ref="$1" type="$2" message="$3" statements

  statements="$(attestations "$ref" "$type")" || return 1
  if [[ -z "$statements" ]]; then
    echo "$message" >&2
    return 1
  fi
  echo "$statements"
}

signature() {
  lookup "$1" "$COSIGN_SIGNATURE" "no signature of $SIGNER_IDENTITY" >/dev/null
}

provenance() {
  local statements

  statements="$(lookup "$1" "$SLSA_PROVENANCE" "no SLSA provenance")" || return 1
  valid_provenance <<<"$statements"
}

# Fails with the message unless one of the statements on stdin matches the
# jq condition.
# shellcheck disable=SC2016
require() {
  local condition="$1" message="$2"

  "$(jq_bin)" -se "any(.[]; $condition)" >/dev/null || {
    echo "$message"
    return 1
  }
}

sbom() {
  local kind="$1" ref="$2" statements

  statements="$(lookup "$ref" "$SPDX_DOCUMENT" "no SPDX SBOM")" || return 1
  if [[ "$kind" == image ]]; then
    require '.predicate["@context"] | tostring | contains("spdx.org/rdf/3")' \
      "no SPDX 3 SBOM of the image" <<<"$statements" || return 1
    require '.predicate.name // "" | endswith("-native")' \
      "no SBOM of the native libraries" <<<"$statements" || return 1
  fi
}

# The vulnerability scan, and the OpenVEX document when it found
# vulnerabilities, see hack/attest-vulns.sh.
scan() {
  local ref="$1" statements findings

  statements="$(lookup "$ref" "$VULNS" "no vulnerability scan")" || return 1
  findings="$("$(jq_bin)" -s 'map(.predicate.scanner.result // [] | length) | max' <<<"$statements")"
  if [[ "$findings" -gt 0 ]]; then
    lookup "$ref" "$OPENVEX" \
      "the scan found $findings vulnerabilities, but there is no OpenVEX document" >/dev/null
  fi
}

build_env() {
  lookup "$1" "$BUILD_ENV" "no build environment" >/dev/null
}

verify_digest() {
  local kind="${1%%=*}" ref="${1#*=}" failed=0

  check "signature" signature "$ref" || failed=1
  if [[ "$kind" == index ]]; then
    return "$failed"
  fi

  check "SLSA provenance" provenance "$ref" || failed=1
  check "SBOM" sbom "$kind" "$ref" || failed=1
  if [[ "$kind" == image || "$kind" == catalog ]]; then
    check "vulnerability scan and VEX" scan "$ref" || failed=1
  fi
  if [[ "$kind" == image ]]; then
    check "build environment" build_env "$ref" || failed=1
  fi

  return "$failed"
}

verify() {
  local ref="${1#*=}"

  prefixed "${ref#"$STAGING_REGISTRY"/}" verify_digest "$1"
}

echo "Verifying the attestations of ${#DIGESTS[@]} digests by $SIGNER_IDENTITY"
if ! parallel_each verify "${DIGESTS[@]}"; then
  echo "Signatures or attestations are missing, see the FAILED checks above" >&2
  exit 1
fi
echo "All ${#DIGESTS[@]} digests carry their signature and attestations"
