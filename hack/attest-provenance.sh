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

# Attests SLSA build provenance (https://slsa.dev/provenance/v1) for each given
# image or artifact, tags are resolved to their digest. The staging build
# records its own run, because Cloud Build only generates provenance into
# Artifact Analysis, which staging projects don't use. The provenance is
# written and signed by the build job itself, so the builder is that job and
# not Google's build platform. Runs from the repository root with the git
# directory and reads the build details from the environment, it does nothing
# outside of Cloud Build:
#
# - BUILD_ID, PROJECT_ID and PROJECT_NUMBER: the Cloud Build substitutions
# - TAG: the image tag of the build
# - BUILD_STARTED: when the build started, in RFC 3339 format, defaults to the
#   content of build/build-started
# - build/build-image: the digest reference of the image the binaries are
#   built in, written by hack/image-cross.sh

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

BUILD_TYPE="$REPOSITORY_URL/blob/main/release.md#staging-attestations"
BUILDER_ID=https://prow.k8s.io/job-history/gs/kubernetes-ci-logs/logs/post-security-profiles-operator-push-image

if ! signing_enabled; then
  echo "Signing disabled, not attesting provenance: $*"
  exit 0
fi

if [[ -z "${BUILD_ID:-}" ]]; then
  echo "Not running in Cloud Build, not attesting provenance: $*"
  exit 0
fi

REFS=()
for ref in "$@"; do
  REFS+=("$(resolve_digest "$ref")")
done

: "${PROJECT_ID:?PROJECT_ID must be set}"
: "${PROJECT_NUMBER:?PROJECT_NUMBER must be set}"
: "${TAG:?TAG must be set}"
BUILD_STARTED="${BUILD_STARTED:-$(cat "$BUILD_DIR/build-started")}"
BUILD_IMAGE="$(cat "$BUILD_DIR/build-image")"

# The nixpkgs revision the build toolchain is pinned to. It materially affects
# the output, so it belongs in resolvedDependencies alongside the source and the
# build image.
# `jq -r` prints the string "null" for a missing node, which would end up in a
# provenance that still verifies while claiming a gitCommit of "null", so fail
# loudly instead. The lock file is addressed relative to this script, not to the
# working directory.
FLAKE_LOCK="$(dirname "${BASH_SOURCE[0]}")/../flake.lock"
NIXPKGS_REV=$("$(jq_bin)" -er \
  '.nodes.nixpkgs.locked.rev // error("no nixpkgs rev in flake.lock")' "$FLAKE_LOCK")
NIXPKGS_URL=$("$(jq_bin)" -er '
  .nodes.nixpkgs.locked
  | if .type != "github" then error("unexpected nixpkgs lock type \(.type)") else . end
  | "git+https://github.com/\(.owner // error("no nixpkgs owner in flake.lock"))/\(.repo // error("no nixpkgs repo in flake.lock"))"
  ' "$FLAKE_LOCK")

# The workspace comes from another user, so git needs to be told to trust it.
COMMIT=$(git -c safe.directory='*' rev-parse HEAD)
REF=$(git -c safe.directory='*' symbolic-ref -q HEAD || echo "$COMMIT")

mkdir -p "$BUILD_DIR/attestations"

for ref in "${REFS[@]}"; do
  predicate="$BUILD_DIR/attestations/$(image_name "$ref").provenance.json"

  "$(jq_bin)" -n \
    --arg buildType "$BUILD_TYPE" \
    --arg builderID "$BUILDER_ID" \
    --arg source "git+$REPOSITORY_URL@$REF" \
    --arg commit "$COMMIT" \
    --arg buildImage "${BUILD_IMAGE%@*}" \
    --arg buildImageDigest "${BUILD_IMAGE#*@sha256:}" \
    --arg nixpkgsURL "$NIXPKGS_URL" \
    --arg nixpkgsRev "$NIXPKGS_REV" \
    --arg tag "$TAG" \
    --arg project "$PROJECT_ID" \
    --arg serviceAccount "${SERVICE_ACCOUNT_EMAIL:-}" \
    --arg invocationID "https://console.cloud.google.com/cloud-build/builds/$BUILD_ID?project=$PROJECT_NUMBER" \
    --arg startedOn "$BUILD_STARTED" \
    --arg finishedOn "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      buildDefinition: {
        buildType: $buildType,
        externalParameters: {
          source: {uri: $source, digest: {gitCommit: $commit}},
          config: "cloudbuild.yaml",
          tag: $tag
        },
        internalParameters: {
          project: $project,
          serviceAccount: $serviceAccount
        },
        resolvedDependencies: [
          {uri: $source, digest: {gitCommit: $commit}},
          {uri: "oci://\($buildImage)", digest: {sha256: $buildImageDigest}},
          {uri: $nixpkgsURL, digest: {gitCommit: $nixpkgsRev}}
        ]
      },
      runDetails: {
        builder: {id: $builderID},
        metadata: {
          invocationId: $invocationID,
          startedOn: $startedOn,
          finishedOn: $finishedOn
        }
      }
    }' >"$predicate"

  attest "$ref" https://slsa.dev/provenance/v1 "$predicate"
done
