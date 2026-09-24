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

# Shared helpers for signing and attesting the staging artifacts. Source this
# file, it does not change shell options.

# The scripts sourcing this file use some of the variables.
# shellcheck disable=SC2034

COSIGN_VERSION=v3.1.3
COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
BOM_VERSION=v0.8.0
BOM_SHA256=cafd00b75a8df860fec54d19b9e24fb48556c0848d0abf9e40cd2eabb11a8710
JQ_VERSION=1.8.2
JQ_SHA256=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f
GOVULNCHECK_VERSION=v1.8.0
CRANE_VERSION=v0.22.1

REPOSITORY_URL=https://github.com/kubernetes-sigs/security-profiles-operator

# Keyless signing needs an OIDC identity, the staging Cloud Build job gets one
# for its service account from the metadata server. SIGN=false skips signing
# and attesting.
SIGN="${SIGN:-true}"
BUILD_DIR="${BUILD_DIR:-build}"
TOOLS_DIR="${TOOLS_DIR:-$BUILD_DIR/tools}"

signing_enabled() {
  [[ "$SIGN" == "true" ]]
}

# Downloads a static binary once, verifies its checksum and prints its path.
# Callers run it in a command substitution, where bash ignores errexit, so every
# failure returns explicitly and prints no path.
download_tool() {
  local name="$1" url="$2" sha256="$3" path="$TOOLS_DIR/$1" download

  if [[ ! -x "$path" ]]; then
    mkdir -p "$TOOLS_DIR" || return 1
    download="$(mktemp "$path.XXXXXX")" || return 1
    if ! curl -sSfL --retry 5 --retry-delay 3 -o "$download" "$url" ||
      ! echo "$sha256  $download" | sha256sum -c - >&2; then
      rm -f "$download"
      echo "Failed to download and verify $name from $url" >&2
      return 1
    fi
    chmod +x "$download" || return 1
    mv "$download" "$path" || return 1
  fi

  echo "$path"
}

# Installs a Go command once, the module checksum database verifies it, and
# prints its path.
install_go_tool() {
  local name="$1" pkg="$2" path

  mkdir -p "$TOOLS_DIR"
  path="$(realpath "$TOOLS_DIR")/$name"
  if [[ ! -x "$path" ]]; then
    GOBIN="$(dirname "$path")" GOFLAGS="" go install "$pkg" >&2
  fi

  echo "$path"
}

cosign_bin() {
  if [[ -n "${COSIGN:-}" ]]; then
    echo "$COSIGN"
    return
  fi
  download_tool cosign \
    "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64" \
    "$COSIGN_SHA256"
}

bom_bin() {
  if [[ -n "${BOM:-}" ]]; then
    echo "$BOM"
    return
  fi
  download_tool bom \
    "https://github.com/kubernetes-sigs/bom/releases/download/$BOM_VERSION/bom-amd64-linux" \
    "$BOM_SHA256"
}

jq_bin() {
  if [[ -n "${JQ:-}" ]]; then
    echo "$JQ"
    return
  fi
  download_tool jq \
    "https://github.com/jqlang/jq/releases/download/jq-$JQ_VERSION/jq-linux-amd64" \
    "$JQ_SHA256"
}

govulncheck_bin() {
  install_go_tool govulncheck "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
}

crane_bin() {
  install_go_tool crane "github.com/google/go-containerregistry/cmd/crane@$CRANE_VERSION"
}

# Prints the digest reference for an image or artifact reference. References
# that already contain a digest are printed as given.
resolve_digest() {
  local ref="$1" digest

  if [[ "$ref" == *@sha256:* ]]; then
    echo "$ref"
    return
  fi

  digest=$(docker buildx imagetools inspect "$ref" --format '{{json .Manifest.Digest}}' | tr -d '"')
  if [[ -z "$digest" ]]; then
    echo "Unable to resolve the digest of $ref" >&2
    return 1
  fi
  echo "${ref%:*}@$digest"
}

# Prefixes the output of a command with a label, so that the output of
# parallel runs stays readable.
prefixed() {
  local label="$1"
  shift
  ("$@") 2>&1 | while IFS= read -r line || [[ -n "$line" ]]; do
    printf '[%s] %s\n' "$label" "$line"
  done
}

# Logs cosign and crane in to a registry with an access token of the Cloud
# Build service account from the metadata server, for build steps without the
# gcloud credential helper. The credentials go to a temporary DOCKER_CONFIG.
registry_login() {
  local registry="$1" token

  token="$(curl -sSf -H 'Metadata-Flavor: Google' \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token |
    "$(jq_bin)" -r .access_token)"
  if [[ -z "$token" || "$token" == null ]]; then
    echo "Unable to get an access token from the metadata server" >&2
    return 1
  fi

  # A fresh configuration, an inherited one may name credential helpers that
  # are not installed in this step.
  DOCKER_CONFIG="$(mktemp -d)"
  export DOCKER_CONFIG
  "$(crane_bin)" auth login "$registry" -u oauth2accesstoken --password-stdin <<<"$token"
}

# Runs a command for each argument in parallel and fails if any run fails.
parallel_each() {
  local cmd="$1" pid failed=0
  local -a pids=()
  shift

  for arg in "$@"; do
    "$cmd" "$arg" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do
    wait "$pid" || failed=1
  done

  return "$failed"
}

# Fails unless the reference names an image by digest.
require_digest() {
  if [[ "$1" != *@sha256:* ]]; then
    echo "Expected an image digest, got $1" >&2
    return 1
  fi
}

# The last path segment of an image reference, for example
# security-profiles-operator-amd64.
image_name() {
  local repo="${1%@*}"
  echo "${repo##*/}"
}

# The OCI package URL of an image digest.
image_purl() {
  local repo="${1%@*}" digest="${1#*@}"
  echo "pkg:oci/${repo##*/}@${digest/:/%3A}?repository_url=$repo"
}

# Signs a predicate as in-toto attestation for an image digest and attaches it
# as Sigstore bundle.
attest() {
  local ref="$1" type="$2" predicate="$3"

  echo "Attesting $type for $ref"
  "$(cosign_bin)" attest --yes --use-signing-config --type "$type" --predicate "$predicate" "$ref"
}

# Extracts the binaries of an image digest into a directory once and prints
# the directory.
extract_binaries() {
  local ref="$1" dir

  dir="$BUILD_DIR/binaries/$(image_name "$ref")"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir.extract"
    "$(crane_bin)" export "$ref" - |
      tar -xf - -C "$dir.extract" security-profiles-operator spoc
    mv "$dir.extract" "$dir"
  fi

  echo "$dir"
}
