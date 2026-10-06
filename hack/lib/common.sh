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

UPSTREAM_REPOSITORY_URL=https://github.com/kubernetes-sigs/security-profiles-operator
# The repository whose GitHub release provenance hack/push-release-artifacts.sh
# verifies, and which the staging attestations name as source. Only a rehearsal
# in a fork sets SPO_REPOSITORY_URL to another one, which needs SIGN=false, see
# doc/release.md#rehearsing-the-release-artifacts-job.
REPOSITORY_URL="${SPO_REPOSITORY_URL:-$UPSTREAM_REPOSITORY_URL}"

# Where the staging build pushes to, and where the image promoter copies the
# staging artifacts to, under the same path.
STAGING_REGISTRY=us-central1-docker.pkg.dev/k8s-staging-images/sp-operator
PRODUCTION_REGISTRY=registry.k8s.io/security-profiles-operator

SLSA_PROVENANCE=https://slsa.dev/provenance/v1
SPDX_DOCUMENT=https://spdx.dev/Document
VULNS=https://in-toto.io/attestation/vulns/v0.2
OPENVEX=https://openvex.dev/ns
BUILD_ENV=https://in-toto.io/attestation/build-env/v1
# The predicate type of the signatures cosign v3 writes, which is what the
# image promoter counts as signature.
COSIGN_SIGNATURE=https://sigstore.dev/cosign/sign/v1

# Keyless signing needs an OIDC identity, the staging Cloud Build job gets one
# for its service account from the metadata server. SIGN=false skips signing
# and attesting.
SIGN="${SIGN:-true}"
BUILD_DIR="${BUILD_DIR:-build}"
TOOLS_DIR="${TOOLS_DIR:-$BUILD_DIR/tools}"

signing_enabled() {
  [[ "$SIGN" == "true" ]]
}

# Nothing signed or attested as the staging build may name another repository.
if [[ "$REPOSITORY_URL" != "$UPSTREAM_REPOSITORY_URL" ]] && signing_enabled; then
  echo "SPO_REPOSITORY_URL is $REPOSITORY_URL instead of $UPSTREAM_REPOSITORY_URL, which needs SIGN=false" >&2
  exit 1
fi

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

# Logs the tools that read the Docker configuration (cosign, crane, spoc and
# helm) in to a registry with an access token of the Cloud Build service
# account from the metadata server. The token is fetched here rather than
# passed through the environment of the build step, where any traced command
# would print it. The credentials go to a temporary DOCKER_CONFIG, which the
# calling shell and its children use afterwards. A later login of the same
# shell replaces the credentials in the same directory, which gets removed
# when the shell exits, see registry_logout.
registry_login() {
  local registry="$1" token auth

  token="$(curl -sSf -H 'Metadata-Flavor: Google' \
    http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token |
    "$(jq_bin)" -r .access_token)"
  if [[ -z "$token" || "$token" == null ]]; then
    echo "Unable to get an access token from the metadata server" >&2
    return 1
  fi

  # A fresh configuration, an inherited one may name credential helpers that
  # are not installed in this step. Written directly, so that the login needs
  # neither docker nor crane. A shell with an EXIT trap of its own has to call
  # registry_logout itself.
  if [[ -z "${REGISTRY_LOGIN_CONFIG:-}" || ! -d "$REGISTRY_LOGIN_CONFIG" ]]; then
    REGISTRY_LOGIN_CONFIG="$(mktemp -d)" || return 1
    if [[ -z "$(trap -p EXIT)" ]]; then
      trap registry_logout EXIT
    fi
  fi
  DOCKER_CONFIG="$REGISTRY_LOGIN_CONFIG"
  export DOCKER_CONFIG
  auth="$(printf 'oauth2accesstoken:%s' "$token" | base64 | tr -d '\n')"
  (
    umask 077
    printf '{"auths":{"%s":{"auth":"%s"}}}\n' "$registry" "$auth" >"$DOCKER_CONFIG/config.json"
  )
  echo "Logged in to $registry"
}

# Removes the credentials of registry_login.
registry_logout() {
  if [[ -n "${REGISTRY_LOGIN_CONFIG:-}" ]]; then
    rm -rf "$REGISTRY_LOGIN_CONFIG"
    REGISTRY_LOGIN_CONFIG=
  fi
}

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

# The OCI package URLs of an image digest: without a repository, which
# matches the digest wherever it is pulled from, in the repository it was
# pushed to and, for staging images, in registry.k8s.io where they are
# promoted to. VEX consumers like the OpenVEX libraries only match a product
# when all of its qualifiers are in the purl they look up.
image_purls() {
  local repo="${1%@*}" digest="${1#*@}" purl
  purl="pkg:oci/${repo##*/}@${digest/:/%3A}"

  echo "$purl"
  echo "$purl?repository_url=$repo"
  if [[ "$repo" == "$STAGING_REGISTRY"/* ]]; then
    echo "$purl?repository_url=$PRODUCTION_REGISTRY/${repo#"$STAGING_REGISTRY"/}"
  fi
}

# Prints the references the image digest is also attested as, from the
# "<ref> <alias>" lines of ATTEST_ALIASES, which hack/attest-images.sh sets for
# the per-arch images in the repository of their manifest list.
attest_aliases() {
  local ref="$1" from to

  while read -r from to; do
    if [[ -n "$from" && "$from" == "$ref" ]]; then
      echo "$to"
    fi
  done <<<"${ATTEST_ALIASES:-}"
}

# Signs a predicate as in-toto attestation for an image digest and its
# aliases, see attest_aliases, and attaches it as Sigstore bundle.
attest() {
  local ref="$1" type="$2" predicate="$3" target
  local -a targets=("$ref")

  while read -r target; do
    targets+=("$target")
  done < <(attest_aliases "$ref")

  for target in "${targets[@]}"; do
    echo "Attesting $type for $target"
    "$(cosign_bin)" attest --yes --use-signing-config --type "$type" --predicate "$predicate" "$target"
  done
}

# Whether the reference names a per-arch operator image, which has binaries
# built by this repository and the SBOM of their native libraries.
operator_image() {
  [[ "$(image_name "$1")" =~ ^security-profiles-operator-(amd64|arm64|ppc64le|s390x)$ ]]
}

# The paths of the binaries in an image that get scanned for vulnerabilities.
# The catalog holds the ones of the opm image it is built from.
image_binaries() {
  if [[ "$(image_name "$1")" == *-catalog ]]; then
    echo usr/bin/opm usr/bin/grpc_health_probe
  else
    echo security-profiles-operator spoc
  fi
}

# Extracts the binaries of an image digest, see image_binaries, and for the
# operator images their SBOM directory, into a directory once and prints the
# directory.
extract_binaries() {
  local ref="$1" dir
  local -a paths

  read -ra paths <<<"$(image_binaries "$ref")"
  if operator_image "$ref"; then
    paths+=(sbom)
  fi

  dir="$BUILD_DIR/binaries/$(image_name "$ref")"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir.extract"
    "$(crane_bin)" export "$ref" - |
      tar -xf - -C "$dir.extract" "${paths[@]}"
    mv "$dir.extract" "$dir"
  fi

  echo "$dir"
}

# Appends an artifact digest that the build pushed or found published to
# $BUILD_DIR/artifact-digests, which hack/verify-attestations.sh checks at the
# end of the build. The kinds are listed there.
record_digest() {
  local kind="$1" ref="$2"

  require_digest "$ref" || return 1
  mkdir -p "$BUILD_DIR"
  echo "$kind $ref" >>"$BUILD_DIR/artifact-digests"
}

# Writes an SPDX 3 SBOM of an artifact file with bom to DIR/sbom.spdx.json and
# prints its path. The SBOM is named DOCUMENT and lists the file by NAME, which
# defaults to the name of FILE, or, for a chart archive (*.tgz), the archive and
# the files in it, with their checksums.
artifact_sbom() {
  local dir="$1" document="$2" file="$3" name="${4:-$(basename "$3")}" bom sbom
  local -a args=(-f "$name")

  mkdir -p "$dir/content" || return 1
  cp "$file" "$dir/content/$name" || return 1
  # bom names the files by the path it is given.
  if [[ "$name" == *.tgz ]]; then
    args=(--archive "$name")
  fi
  bom="$(bom_bin)" || return 1
  if [[ "$bom" == */* ]]; then
    bom="$(realpath "$bom")" || return 1
  fi
  sbom="$(realpath "$dir")/sbom.spdx.json" || return 1
  (cd "$dir/content" && "$bom" generate --format spdx3-json --name "$document" "${args[@]}" -o "$sbom") >&2 || return 1

  echo "$sbom"
}

# Signs and attests a security profile that the build pushed or, with a third
# argument true, found published, see hack/sign-published.sh and
# hack/attest-artifact.sh, when the digest its tag points to holds FILE: the
# build only signs and attests what it would have pushed itself. spoc signs
# what it pushes, so only published profiles get signed here. The tag is
# resolved once, so that the compared digest is the signed and attested one. A
# profile with another content is left alone with a warning, and
# hack/verify-attestations.sh does not check it: the build cannot replace it,
# because its tag is taken, so failing would only fail every build until the
# tag changes. The image promoter still checks it if it is promoted. SPOC is
# the spoc binary.
attest_profile() {
  local ref="$1" file="$2" published="${3:-false}" digest output
  local pulled="$BUILD_DIR/published-profile.json"

  # Outside of Cloud Build only published profiles get signed, see
  # hack/attest-artifact.sh.
  if ! signing_enabled || [[ -z "${BUILD_ID:-}" && "$published" != true ]]; then
    return 0
  fi

  digest="$(resolve_digest "$ref")" || return 1
  if ! output="$("${SPOC:-$BUILD_DIR/spoc}" pull -s -o "$pulled" "$digest" 2>&1)"; then
    echo "Unable to pull $digest: $output" >&2
    return 1
  fi
  if ! cmp -s "$pulled" "$file"; then
    echo "WARNING: $ref (${digest#*@}) differs from $file, neither signing nor attesting it" >&2
    return 0
  fi

  if [[ "$published" == true ]]; then
    "$(dirname "${BASH_SOURCE[0]}")/../sign-published.sh" "$digest" || return 1
  fi
  "$(dirname "${BASH_SOURCE[0]}")/../attest-artifact.sh" "$digest" "$file" profile.json
}

# The builder ID of the provenance the build writes: the Cloud Build
# configuration of the repository as the service account of the staging
# project. Fails without the service account, which a builder ID has to name
# to be trusted.
builder_id() {
  if [[ -z "${PROJECT_ID:-}" || -z "${SERVICE_ACCOUNT_EMAIL:-}" ]]; then
    echo "PROJECT_ID and SERVICE_ACCOUNT_EMAIL must be set for the builder ID" >&2
    return 1
  fi
  echo "https://cloudbuild.googleapis.com/projects/$PROJECT_ID/serviceAccounts/$SERVICE_ACCOUNT_EMAIL/cloudbuild.yaml"
}

# A resolved dependency of the provenance for an image digest, with an
# optional name.
# shellcheck disable=SC2016
oci_dependency() {
  local ref="$1" name="${2:-}"

  require_digest "$ref" || return 1
  "$(jq_bin)" -cn --arg uri "oci://${ref%@*}" --arg digest "${ref#*@sha256:}" --arg name "$name" \
    '{uri: $uri, digest: {sha256: $digest}} + if $name == "" then {} else {name: $name} end'
}

# A resolved dependency of the provenance for a file, by its SHA-256 digest,
# with an optional URI it was downloaded from.
# shellcheck disable=SC2016
file_dependency() {
  local name="$1" path="$2" uri="${3:-}" digest

  digest="$(sha256sum "$path" | cut -d' ' -f1)" || return 1
  "$(jq_bin)" -cn --arg name "$name" --arg digest "$digest" --arg uri "$uri" \
    '{name: $name, digest: {sha256: $digest}} + if $uri == "" then {} else {uri: $uri} end'
}

# The resolved dependency of the provenance for the spoc binary that converts
# and pushes the profiles: its SHA-256 digest and, when SPOC_IMAGE is set, the
# image digest it was copied from.
# shellcheck disable=SC2016
spoc_dependency() {
  file_dependency spoc "$1" |
    "$(jq_bin)" -c --arg image "${SPOC_IMAGE:-}" \
      '. + if $image == "" then {} else {annotations: {image: $image}} end'
}

# The resolved dependencies of the binaries the build compiles, as JSON array:
# the build image, from build/build-image, which hack/image-cross.sh writes,
# and the nixpkgs revision its toolchain is pinned to.
# shellcheck disable=SC2016
toolchain_dependencies() {
  local build_image flake_lock nixpkgs_rev nixpkgs_url

  build_image="$(cat "$BUILD_DIR/build-image")" || return 1
  require_digest "$build_image" || return 1
  # `jq -r` prints the string "null" for a missing node, which would end up in
  # a provenance that still verifies while claiming a gitCommit of "null", so
  # fail loudly instead. The lock file is addressed relative to this file, not
  # to the working directory.
  flake_lock="$(dirname "${BASH_SOURCE[0]}")/../../flake.lock"
  nixpkgs_rev=$("$(jq_bin)" -er \
    '.nodes.nixpkgs.locked.rev // error("no nixpkgs rev in flake.lock")' "$flake_lock") || return 1
  nixpkgs_url=$("$(jq_bin)" -er '
    .nodes.nixpkgs.locked
    | if .type != "github" then error("unexpected nixpkgs lock type \(.type)") else . end
    | "git+https://github.com/\(.owner // error("no nixpkgs owner in flake.lock"))/\(.repo // error("no nixpkgs repo in flake.lock"))"
    ' "$flake_lock") || return 1

  "$(jq_bin)" -cn \
    --arg buildImage "${build_image%@*}" \
    --arg buildImageDigest "${build_image#*@sha256:}" \
    --arg nixpkgsURL "$nixpkgs_url" \
    --arg nixpkgsRev "$nixpkgs_rev" \
    '[
      {uri: "oci://\($buildImage)", digest: {sha256: $buildImageDigest}},
      {uri: $nixpkgsURL, digest: {gitCommit: $nixpkgsRev}}
    ]'
}

# The cosign flags that select the signatures and attestations of the build:
# SIGNER_IDENTITY and SIGNER_OIDC_ISSUER for an exact match, else
# SIGNER_IDENTITY_REGEXP and SIGNER_OIDC_ISSUER_REGEXP. One flag or value per
# line. Fails when neither is set, they never default to any identity.
signer_args() {
  if [[ -n "${SIGNER_IDENTITY:-}" && -n "${SIGNER_OIDC_ISSUER:-}" ]]; then
    printf '%s\n' --certificate-identity "$SIGNER_IDENTITY" \
      --certificate-oidc-issuer "$SIGNER_OIDC_ISSUER"
  elif [[ -n "${SIGNER_IDENTITY_REGEXP:-}" && -n "${SIGNER_OIDC_ISSUER_REGEXP:-}" ]]; then
    printf '%s\n' --certificate-identity-regexp "$SIGNER_IDENTITY_REGEXP" \
      --certificate-oidc-issuer-regexp "$SIGNER_OIDC_ISSUER_REGEXP"
  else
    echo "No signer identity configured" >&2
    return 1
  fi
}

# Whether the build identity signed the image digest, see signer_args: with a
# cosign signature, which other bundles like attestations are not, even though
# cosign verify accepts them. Returns 1 when it did not and 2 when the lookup
# failed, see attestations.
signed() {
  local statements

  statements="$(attestations "$1" "$COSIGN_SIGNATURE")" || return 2
  [[ -n "$statements" ]]
}

# Prints the in-toto statements of the predicate type attached to an image
# digest that the build identity signed, see signer_args, and that are about
# the digest, one per line. Prints nothing when there are none. Other errors of
# cosign, for example of the registry, are retried, and fail when they persist.
# shellcheck disable=SC2016
attestations() {
  local ref="$1" type="$2" identity out errors attempt
  local -a args

  require_digest "$ref" || return 1
  identity="$(signer_args)" || return 1
  mapfile -t args <<<"$identity"
  errors="$(mktemp)" || return 1

  for attempt in 1 2 3; do
    if out="$("$(cosign_bin)" verify-attestation --type "$type" "${args[@]}" "$ref" 2>"$errors")"; then
      break
    fi
    out=""
    # How cosign says that it found no attestation of the type by the
    # identity, which is no error here.
    if grep -q -E 'no matching attestations|none of the attestations matched' "$errors"; then
      break
    fi
    if [[ $attempt -eq 3 ]]; then
      echo "Unable to look up the $type attestations of $ref: $(grep -m1 . "$errors")" >&2
      rm -f "$errors"
      return 1
    fi
    sleep $((attempt * 5))
  done
  rm -f "$errors"

  [[ -n "$out" ]] || return 0
  "$(jq_bin)" -c --arg digest "${ref#*@}" \
    '.payload | @base64d | fromjson
    | select(any(.subject[]?; "sha256:\(.digest.sha256)" == $digest))' <<<"$out"
}

# Reads in-toto statements and succeeds when one of them is SLSA provenance of
# this build as the image promoter checks it: with the builder ID of builder_id
# and this repository as source. The statements are about the digest already,
# see attestations. Prints why none counts otherwise.
# shellcheck disable=SC2016
valid_provenance() {
  local builder statements problems
  local -a args

  builder="$(builder_id)" || return 1
  args=(--arg builder "$builder" --arg source "${REPOSITORY_URL#https://}")
  statements="$(cat)"
  if [[ -z "$statements" ]]; then
    echo "no SLSA provenance"
    return 1
  fi

  # The source is a URI or a resource descriptor, compared without the ref.
  problems='
    def repo: (if type == "object" then .uri else . end // "")
      | sub("^git\\+"; "") | sub("^https?://"; "") | sub("@.*$"; "") | sub("\\.git$"; "");
    def problems: [
      (.predicate.runDetails.builder.id // "" | select(. != $builder)
        | "builder ID \"\(.)\" is not \($builder)"),
      (.predicate.buildDefinition.externalParameters.source | repo | select(. != $source)
        | "source \"\(.)\" is not \($source)")
    ];'
  if "$(jq_bin)" -se "${args[@]}" "$problems any(.[]; problems == [])" <<<"$statements" >/dev/null; then
    return 0
  fi
  "$(jq_bin)" -sr "${args[@]}" "$problems .[] | problems[] | \"provenance with \\(.)\"" <<<"$statements"
  return 1
}

# Reads the tags of a staging repository and prints the ones of the images
# Cloud Build built for COMMIT. The image builder tags them
# vYYYYMMDD-<git describe --tags --always --dirty>: while the commit has no
# tag, that ends with -g<abbreviated commit>, and once RELEASE_TAG points to
# the commit, for example when the job ran after the tag was pushed, it is
# vYYYYMMDD-RELEASE_TAG. RELEASE_TAG is optional.
staging_commit_tags() {
  local commit="$1" release="${2:-}" tag describe

  while read -r tag; do
    [[ "$tag" =~ ^v[0-9]{8}-(.+)$ ]] || continue
    describe="${BASH_REMATCH[1]}"
    if [[ -n "$release" && "$describe" == "$release" ]] ||
      [[ "$describe" =~ -g([0-9a-f]{7,40})$ && "$commit" == "${BASH_REMATCH[1]}"* ]]; then
      echo "$tag"
    fi
  done
}
