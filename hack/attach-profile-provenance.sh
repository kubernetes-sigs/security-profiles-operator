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

# Attaches the SLSA Build L3 provenance of the build workflow to the security
# profiles that the staging build published, see
# doc/release.md#security-profiles. The profiles job of the build workflow
# publishes the profiles of every push to main to a throwaway registry, where
# they get the same digests as in staging, and the isolated provenance
# workflow attests them and stores the provenance as artifact attestation of
# the repository. This script fetches it by digest from the attestation API of
# GitHub, waiting up to WAIT_TIMEOUT seconds for the workflow of this commit
# for the profiles this build pushed, but no longer than BUILD_TIMEOUT leaves
# of the build. It verifies that the provenance workflow of main signed it for
# the build workflow at the commit the provenance names, on a GitHub hosted
# runner, and attaches it as OCI referrer, like hack/push-release-artifacts.sh
# does for the release artifacts. The provenance of any commit of main counts: a
# profile has the same digest whenever it is built from the same content. A
# profile that carries provenance of the provenance workflow already, of main
# or a release, gets no other, so that the image promoter carries one per
# profile. Profiles found published get a single lookup without waiting:
# their workflow ran long ago, and one that can't reproduce a staging digest,
# for example of a profile recorded again under its version, never attests
# it. A late or failed workflow, or the rate limit of the API, only logs a
# warning: the build of a later commit looks the profile up again and attaches
# the provenance, and hack/verify-attestations.sh does not require it.
#
# Reads the tags of the profiles from $BUILD_DIR/profile-refs, and of the
# ones this build pushed from $BUILD_DIR/profile-pushed-refs, which
# hack/push-base-profiles.sh and hack/push-test-artifacts.sh write.

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

WAIT_TIMEOUT="${WAIT_TIMEOUT:-600}"
WAIT_INTERVAL="${WAIT_INTERVAL:-60}"
# The timeout of the whole build in seconds, which started at the time in
# $BUILD_DIR/build-started, see hack/image-cross.sh. The wait ends a margin
# before it. Unset, only WAIT_TIMEOUT bounds the wait.
BUILD_TIMEOUT="${BUILD_TIMEOUT:-}"
BUILD_TIMEOUT_MARGIN=120
# Raises the rate limit of the attestation API when set.
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
REF=refs/heads/main
WORKFLOW=.github/workflows/build.yml
SIGNER_WORKFLOW="$PROVENANCE_SIGNER_WORKFLOW"
OIDC_ISSUER="$GITHUB_OIDC_ISSUER"
ATTESTATIONS_URL="https://api.github.com/repos/${REPOSITORY_URL#https://github.com/}/attestations"
DIR="$BUILD_DIR/profile-provenance"
cosign_bin >/dev/null
CRANE="$(crane_bin)"
JQ="$(jq_bin)"

if [[ ! -s "$BUILD_DIR/profile-refs" ]]; then
  echo "No profiles to attach provenance to"
  exit 0
fi
rm -rf "$DIR"
mkdir -p "$DIR"

# This step has no credential helper for the registry.
if [[ -n "${BUILD_ID:-}" ]]; then
  registry_login "$(head -n1 "$BUILD_DIR/profile-refs" | cut -d/ -f1)"
fi

# The time a reset of the rate limit of the attestation API is due at, in
# seconds since the epoch, once a request hit it.
RATE_LIMIT_RESET=''

# Whether the digest carries provenance of the provenance workflow, of main or
# a release, as the image promoter finds it.
has_provenance() {
  local statements

  statements="$(SIGNER_IDENTITY='' SIGNER_OIDC_ISSUER='' \
    SIGNER_IDENTITY_REGEXP="^${SIGNER_WORKFLOW//./\\.}@(refs/heads/main|refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+)\$" \
    SIGNER_OIDC_ISSUER_REGEXP="^${OIDC_ISSUER//./\\.}\$" \
    attestations "$1" "$SLSA_PROVENANCE")" || return 2
  [[ -n "$statements" ]]
}

# Fetches the attestations of a digest from GitHub and writes the bundles of
# provenance by the build workflow of main about it, created on a GitHub
# hosted runner, to $DIR/bundles, named by their digest. Without GITHUB_TOKEN
# the API allows 60 requests an hour, shared by the builds behind the same
# address, which is why bundles are kept for the other profiles they are
# about, each round fetches for one profile only, failed requests are logged
# with their status, and no request is sent anymore once the limit is hit,
# see RATE_LIMIT_RESET.
fetch_provenance() {
  local digest="$1" response="$DIR/attestations.json" headers="$DIR/attestations.headers"
  local status entry bundle url remaining reset
  local -a auth=()

  if [[ -n "$GITHUB_TOKEN" ]]; then
    auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  fi
  status="$(curl -sSL --retry 3 --retry-delay 5 -o "$response" -D "$headers" -w '%{http_code}' \
    -H 'Accept: application/vnd.github+json' "${auth[@]}" \
    "$ATTESTATIONS_URL/$digest?per_page=100" 2>/dev/null)" || status=000
  case "$status" in
  200) ;;
  404) return 0 ;; # nothing attested yet
  403 | 429)
    remaining="$(sed -n 's/^x-ratelimit-remaining: *\([0-9]*\).*/\1/Ip' "$headers" | tail -n1)"
    reset="$(sed -n 's/^x-ratelimit-reset: *\([0-9]*\).*/\1/Ip' "$headers" | tail -n1)"
    if [[ "$remaining" == 0 || "$status" == 429 ]]; then
      RATE_LIMIT_RESET="${reset:-0}"
      echo "WARNING: the attestation API of GitHub rate limits this build until" \
        "$(date -u -d "@$RATE_LIMIT_RESET" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown), not looking up any more provenance" >&2
      return 0
    fi
    echo "WARNING: fetching the attestations of $digest from GitHub failed with HTTP status $status" >&2
    return 0
    ;;
  *)
    echo "WARNING: fetching the attestations of $digest from GitHub failed with HTTP status $status" >&2
    return 0
    ;;
  esac
  mkdir -p "$DIR/bundles"
  while read -r entry; do
    [[ -n "$entry" ]] || continue
    bundle="$("$JQ" -c '.bundle // empty' <<<"$entry")"
    # The API can leave the bundle out and only link it.
    if [[ -z "$bundle" ]]; then
      url="$("$JQ" -r '.bundle_url // empty' <<<"$entry")"
      [[ -n "$url" ]] || continue
      if ! bundle="$(curl -sSfL --retry 3 --retry-delay 5 "$url" 2>/dev/null)"; then
        echo "WARNING: unable to fetch the bundle of an attestation of $digest from $url" >&2
        continue
      fi
      if ! bundle="$("$JQ" -c . <<<"$bundle" 2>/dev/null)"; then
        echo "WARNING: the bundle of an attestation of $digest at $url is no JSON document, skipping it" >&2
        continue
      fi
    fi
    if statement "$bundle" | github_workflow_provenance "$WORKFLOW" "$REF" "" "$digest" 2>/dev/null; then
      printf '%s' "$bundle" >"$DIR/bundles/$(printf '%s' "$bundle" | sha256sum | cut -d' ' -f1).json"
    fi
  done < <("$JQ" -c '.attestations[]?' "$response" 2>/dev/null)
}

# The in-toto statement of a bundle.
statement() {
  "$JQ" -r '.dsseEnvelope.payload' <<<"$1" | base64 -d
}

# The commit of main the provenance of a bundle names.
provenance_commit() {
  "$JQ" -r '.dsseEnvelope.payload' "$1" | base64 -d | "$JQ" -r --arg repo "$REPOSITORY_URL" --arg ref "$REF" '
    [.predicate.buildDefinition.resolvedDependencies[]?
      | select(.uri == "git+\($repo)@\($ref)") | .digest.gitCommit // empty]
    | if length == 1 and (.[0] | test("^[0-9a-f]{40}$")) then .[0] else error("no single commit") end'
}

# Verifies a provenance bundle about a profile manifest and attaches it.
attach() {
  local repo="$1" digest="$2" bundle="$3" manifest="$DIR/${2#sha256:}.manifest" commit desc

  if ! statement "$(cat "$bundle")" | "$JQ" -e --arg digest "${digest#sha256:}" \
    'any(.subject[]; .digest.sha256 == $digest)' >/dev/null 2>&1; then
    return 1
  fi
  commit="$(provenance_commit "$bundle")" || return 1
  "$CRANE" manifest "$repo@$digest" >"$manifest" || return 1
  if [[ "sha256:$(sha256sum "$manifest" | cut -d' ' -f1)" != "$digest" ]]; then
    echo "$repo@$digest returned another manifest" >&2
    return 1
  fi
  verify_github_provenance "$bundle" "$REF" "$commit" push "$manifest" || return 1
  desc="$("$JQ" -cn --arg mt "$("$JQ" -r .mediaType "$manifest")" --arg d "$digest" \
    --argjson s "$(stat -c %s "$manifest")" '{mediaType: $mt, digest: $d, size: $s}')"
  echo "Attaching the provenance of $WORKFLOW at $commit"
  attach_bundle "$repo" "$desc" "$bundle"
}

# Attaches the first bundle in $DIR/bundles that verifies for the digest.
attach_known() {
  local digest_ref="$1" bundle

  for bundle in "$DIR"/bundles/*.json; do
    [[ -f "$bundle" ]] || continue
    if attach "${digest_ref%@*}" "${digest_ref#*@}" "$bundle"; then
      return 0
    fi
  done
  return 1
}

# The digests of the profiles that have no provenance of the workflow yet,
# and of those among them that this build pushed.
declare -A pending=() pushed=()
while read -r ref; do
  [[ -n "$ref" ]] || continue
  # With crane, the step has no docker for resolve_digest.
  if [[ "$ref" == *@sha256:* ]]; then
    digest_ref="$ref"
  elif digest="$("$CRANE" digest "$ref")"; then
    digest_ref="${ref%:*}@$digest"
  else
    echo "WARNING: unable to resolve the digest of $ref" >&2
    continue
  fi
  status=0
  has_provenance "$digest_ref" || status=$?
  case "$status" in
  0) echo "Already has provenance of the provenance workflow: $ref (${digest_ref#*@})" ;;
  1)
    pending["$digest_ref"]="$ref"
    if [[ -f "$BUILD_DIR/profile-pushed-refs" ]] && grep -qxF -- "$ref" "$BUILD_DIR/profile-pushed-refs"; then
      pushed["$digest_ref"]=true
    fi
    ;;
  *) echo "WARNING: unable to look up the provenance of $digest_ref" >&2 ;;
  esac
done < <(sort -u "$BUILD_DIR/profile-refs")

# One lookup for every pending profile. A bundle of the workflow run that
# attested several profiles is about all of them, so the first fetch often
# covers the others.
for digest_ref in "${!pending[@]}"; do
  if ! attach_known "$digest_ref"; then
    [[ -z "$RATE_LIMIT_RESET" ]] || continue
    fetch_provenance "${digest_ref#*@}"
    attach_known "$digest_ref" || continue
  fi
  unset "pending[$digest_ref]"
done

# Only the workflow of this commit can still attest the profiles this build
# pushed. The others were published before, without provenance of main.
for digest_ref in "${!pending[@]}"; do
  if [[ -z "${pushed[$digest_ref]:-}" ]]; then
    echo "WARNING: no provenance of $WORKFLOW on main for ${pending[$digest_ref]} ($digest_ref), which was published before," \
      "see doc/release.md#security-profiles" >&2
    unset "pending[$digest_ref]"
  fi
done

wait_timeout="$WAIT_TIMEOUT"
if [[ -n "$BUILD_TIMEOUT" ]]; then
  if ! started="$(date -u -d "$(cat "$BUILD_DIR/build-started")" +%s)"; then
    echo "Unable to read the start of the build from $BUILD_DIR/build-started" >&2
    exit 1
  fi
  left=$((started + BUILD_TIMEOUT - BUILD_TIMEOUT_MARGIN - $(date -u +%s)))
  if [[ $left -lt $wait_timeout ]]; then
    wait_timeout=$((left > 0 ? left : 0))
  fi
fi
deadline=$((SECONDS + wait_timeout))
while [[ ${#pending[@]} -gt 0 ]]; do
  if [[ $SECONDS -ge $deadline || -n "$RATE_LIMIT_RESET" ]]; then
    reason="after ${wait_timeout}s"
    if [[ -n "$RATE_LIMIT_RESET" ]]; then
      reason="within the rate limit of the attestation API"
    fi
    for digest_ref in "${!pending[@]}"; do
      echo "WARNING: no provenance of $WORKFLOW on main for ${pending[$digest_ref]} ($digest_ref) $reason," \
        "the build of a later commit attaches it, see doc/release.md#security-profiles" >&2
    done
    break
  fi
  echo "Waiting for the provenance of the profiles: ${pending[*]}"
  sleep "$WAIT_INTERVAL"

  # One request a round: the run that attests one of the profiles attests
  # all of them.
  digest_refs=("${!pending[@]}")
  fetch_provenance "${digest_refs[0]#*@}"
  for digest_ref in "${digest_refs[@]}"; do
    if attach_known "$digest_ref"; then
      unset "pending[$digest_ref]"
    fi
  done
done
