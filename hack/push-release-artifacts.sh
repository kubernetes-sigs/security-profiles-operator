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

# Publishes the spoc binaries and the Helm chart of the GitHub release $TAG to
# the staging registry and attaches the provenance of the release to the
# per-arch images there (see images), so that they can be promoted to
# registry.k8s.io, see
# doc/release.md#oci-artifacts. Nothing is built here: the GitHub workflows of
# the release build the OCI image layouts (hack/oci-layout.sh) and attest their
# manifest digests with SLSA Build L3 provenance. This script waits until the
# release has the assets, verifies the provenance of every manifest, pushes the
# manifests byte for byte, so that they keep the attested digests, and attaches
# the provenance bundles as OCI referrers. The manifests get signed with the
# identity of the staging build as well and get SBOM attestations of it, the
# spoc SBOMs of the release and one bom writes for the chart archive, unless it
# signed and attested them already, see SIGNER_IDENTITY. SIGN=false skips that.
# Last, every manifest is verified to carry the signature, the provenance and
# the SBOMs.

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

TAG="${TAG:-}"
if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "TAG has to be a release tag like v1.2.3, got '$TAG'" >&2
  exit 1
fi
VERSION="${TAG#v}"

REGISTRY="${REGISTRY:-$STAGING_REGISTRY}"
RELEASE_URL="${RELEASE_URL:-$REPOSITORY_URL/releases/download/$TAG}"
# The release is created by hand after the tag got pushed, and its workflows
# take a few minutes.
WAIT_TIMEOUT="${WAIT_TIMEOUT:-7200}"
WAIT_INTERVAL="${WAIT_INTERVAL:-60}"
# How long to wait for the provenance of the per-arch images once spoc and the
# chart are published. Its workflow starts with theirs and is usually done by
# then, both waits together stay below the timeout of cloudbuild-release.yaml.
IMAGE_WAIT_TIMEOUT="${IMAGE_WAIT_TIMEOUT:-2700}"
# The registry to log in to once the assets are there, access tokens of the
# metadata server only last an hour.
LOGIN_REGISTRY="${LOGIN_REGISTRY:-}"
# The commit the tag points to, checked against the provenance. The workspace
# comes from another user, so git needs to be told to trust it.
COMMIT="${COMMIT:-$(git -c safe.directory='*' rev-parse HEAD)}"

SIGNER_WORKFLOW="$REPOSITORY_URL/.github/workflows/provenance.yml"
OIDC_ISSUER=https://token.actions.githubusercontent.com
# The identity of the staging build, whose signatures and SBOM attestations
# are not added again on a rerun, see signer_args. Without it every run signs
# and attests, an attacker's signature must never count as signed, and the
# final verification is skipped.
SIGNER_IDENTITY="${SIGNER_IDENTITY:-}"
SIGNER_OIDC_ISSUER=https://accounts.google.com
EMPTY_CONFIG='{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2}'

CHART=security-profiles-operator
SPOC_ARCHES=(amd64 arm64 ppc64le s390x)
SPOC_FILES=("${SPOC_ARCHES[@]/#/spoc.}")
SPOC_SBOMS=(spoc.spdx.json spoc-native.spdx.json)
CHART_FILES=("$CHART-$VERSION.tgz")
ASSETS=(
  "${SPOC_FILES[@]}" "${SPOC_SBOMS[@]}" spoc.intoto.jsonl spoc-oci-layout.tar
  "${CHART_FILES[@]}" "$CHART-$VERSION.intoto.jsonl" "$CHART-$VERSION-oci-layout.tar"
)

DIR="$BUILD_DIR/release-artifacts/$TAG"
COSIGN="$(cosign_bin)"
CRANE="$(crane_bin)"
JQ="$(jq_bin)"

# The per-arch images of the release are built and pushed by Cloud Build for
# the tagged commit on main, the image-reproducible workflow of the release
# builds them again from the tag and attests their manifest digests in
# images.intoto.jsonl, see doc/release.md#per-arch-images. It is not in
# ASSETS, the job only waits for it after publishing spoc and the chart.
IMAGE=security-profiles-operator
IMAGE_BUNDLE=images.intoto.jsonl
IMAGE_WORKFLOW=.github/workflows/image-reproducible.yml

# Downloads release assets, waiting up to TIMEOUT seconds for the ones that are
# not uploaded yet. Assets are only visible once their upload is complete.
download_assets() {
  local timeout="$1" asset deadline
  local -a missing
  shift
  deadline=$((SECONDS + timeout))

  mkdir -p "$DIR"
  while :; do
    missing=()
    for asset in "$@"; do
      [[ -f "$DIR/$asset" ]] && continue
      if curl -sSfL --retry 3 --retry-delay 5 -o "$DIR/$asset.download" "$RELEASE_URL/$asset" 2>/dev/null; then
        mv "$DIR/$asset.download" "$DIR/$asset"
      else
        rm -f "$DIR/$asset.download"
        missing+=("$asset")
      fi
    done

    [[ ${#missing[@]} -eq 0 ]] && return 0
    if [[ $SECONDS -ge $deadline ]]; then
      echo "Timed out waiting for the release assets of $TAG: ${missing[*]}" >&2
      return 1
    fi
    echo "Waiting for the release assets of $TAG: ${missing[*]}"
    sleep "$WAIT_INTERVAL"
  done
}

# Checks that a blob of a layout exists with the size and digest of its
# descriptor.
check_blob() {
  local layout="$1" desc="$2" digest size file

  digest="$("$JQ" -r .digest <<<"$desc")"
  size="$("$JQ" -r .size <<<"$desc")"
  if [[ ! "$digest" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Unexpected digest $digest in $layout" >&2
    return 1
  fi
  file="$layout/blobs/sha256/${digest#sha256:}"
  if [[ ! -f "$file" || "$(stat -c %s "$file")" != "$size" ]] ||
    [[ "$(sha256sum "$file" | cut -d' ' -f1)" != "${digest#sha256:}" ]]; then
    echo "Blob $digest of $layout is missing or does not match its descriptor" >&2
    return 1
  fi
}

# Checks a manifest or index and everything it references, and prints the
# descriptors of the manifests, the given one first.
check_manifest() {
  local layout="$1" desc="$2" file child children

  check_blob "$layout" "$desc"
  file="$layout/blobs/sha256/$("$JQ" -r '.digest | ltrimstr("sha256:")' <<<"$desc")"
  "$JQ" -c '{mediaType, digest, size}' <<<"$desc"

  case "$("$JQ" -r .mediaType <<<"$desc")" in
  application/vnd.oci.image.index.v1+json)
    children="$("$JQ" -c '.manifests[]' "$file")"
    while read -r child; do
      check_manifest "$layout" "$child"
    done <<<"$children"
    ;;
  application/vnd.oci.image.manifest.v1+json)
    children="$("$JQ" -c '.config, .layers[]' "$file")"
    while read -r child; do
      check_blob "$layout" "$child"
    done <<<"$children"
    ;;
  *)
    echo "Unexpected media type in $desc" >&2
    return 1
    ;;
  esac
}

# Restores the layout of a packed layout tar and the release assets that are
# its layers, checks it and prints the descriptors of its manifests.
unpack_layout() {
  local name="$1" tar="$2" layout="$DIR/$1" file
  shift 2

  rm -rf "$layout"
  mkdir -p "$layout"
  tar -xf "$DIR/$tar" -C "$layout" --no-same-owner --no-same-permissions
  # The tar is no provenance subject, a link in it could redirect the copies
  # below or the blob checks.
  if [[ -n "$(find "$layout" ! -type f ! -type d)" ]]; then
    echo "The layout $tar may only hold files and directories" >&2
    return 1
  fi
  for file in "$@"; do
    cp "$DIR/$file" "$layout/blobs/sha256/$(sha256sum "$DIR/$file" | cut -d' ' -f1)"
  done

  if [[ "$("$JQ" '.manifests | length' "$layout/index.json")" != 1 ]]; then
    echo "The layout $tar has to hold exactly one manifest" >&2
    return 1
  fi
  check_manifest "$layout" "$("$JQ" -c '.manifests[0]' "$layout/index.json")"
}

# Succeeds when one of the in-toto statements on stdin is provenance of the
# release workflow for the tag and commit, created on a GitHub hosted runner.
release_provenance() {
  local workflow="$1"

  "$JQ" -se \
    --arg type "$SLSA_PROVENANCE" --arg repo "$REPOSITORY_URL" --arg ref "refs/tags/$TAG" \
    --arg commit "$COMMIT" --arg workflow "$workflow" '
      any(.[];
        .predicateType == $type and
        .predicate.buildDefinition.externalParameters.workflow == {ref: $ref, repository: $repo, path: $workflow} and
        .predicate.buildDefinition.internalParameters.github.runner_environment == "github-hosted" and
        any(.predicate.buildDefinition.resolvedDependencies[]?;
          .uri == "git+\($repo)@\($ref)" and .digest.gitCommit == $commit))
    ' >/dev/null
}

# Verifies that the provenance bundle is GitHub artifact attestation of the
# provenance workflow for the tag and commit, created for the GitHub release,
# about each file. Files in the blobs of a layout are named by their digest.
verify_provenance() {
  local bundle="$1" workflow="$2" file
  shift 2

  "$JQ" -r .dsseEnvelope.payload "$bundle" | base64 -d | release_provenance "$workflow" || {
    echo "The provenance $bundle is not about $workflow at $TAG ($COMMIT) on GitHub hosted runners" >&2
    return 1
  }

  for file in "$@"; do
    if [[ "$file" == */blobs/sha256/* ]]; then
      echo "Verifying the provenance of sha256:${file##*/}"
    else
      echo "Verifying the provenance of ${file##*/}"
    fi
    "$COSIGN" verify-blob-attestation \
      --bundle "$bundle" \
      --type "$SLSA_PROVENANCE" \
      --certificate-identity "$SIGNER_WORKFLOW@refs/tags/$TAG" \
      --certificate-oidc-issuer "$OIDC_ISSUER" \
      --certificate-github-workflow-repository "${REPOSITORY_URL#https://github.com/}" \
      --certificate-github-workflow-ref "refs/tags/$TAG" \
      --certificate-github-workflow-sha "$COMMIT" \
      --certificate-github-workflow-trigger release \
      "$file"
  done
}

# Pushes a layout unless the tag exists already with the same digest. A tag
# that points to anything else is never overwritten.
push_layout() {
  local layout="$1" ref="$2" desc="$3" digest current err="$DIR/crane-digest.err"

  # Only stdout is the digest, crane logs warnings like a fallback from HEAD
  # to GET requests to stderr.
  digest="$("$JQ" -r .digest <<<"$desc")"
  if current="$("$CRANE" digest "$ref" 2>"$err")"; then
    if [[ "$current" == "$digest" ]]; then
      echo "Already published: $ref@$digest"
      return 0
    fi
    echo "$ref exists already with digest $current instead of $digest" >&2
    return 1
  fi
  if ! grep -qiE 'not found|unknown' "$err"; then
    echo "Unable to check whether $ref exists: $(cat "$err")" >&2
    return 1
  fi

  # The index.json of the layout holds the manifest or index to push, crane
  # pushes that one without --index.
  echo "Pushing $ref@$digest"
  "$CRANE" push "$layout" "$ref"
  current="$("$CRANE" digest "$ref")"
  if [[ "$current" != "$digest" ]]; then
    echo "Pushed $ref as $current instead of $digest" >&2
    return 1
  fi
}

# Attaches a provenance bundle to a manifest as OCI referrer, the way cosign
# attaches Sigstore bundles. The referrer has no creation time, so the same
# bundle always gets the same referrer digest and is attached only once.
attach_bundle() {
  local repo="$1" desc="$2" bundle="$3" layout layer manifest

  layout="$(mktemp -d "$DIR/referrer.XXXXXX")"
  mkdir -p "$layout/blobs/sha256"
  printf '{"imageLayoutVersion":"1.0.0"}' >"$layout/oci-layout"
  printf '{}' >"$layout/blobs/sha256/$("$JQ" -r '.digest | ltrimstr("sha256:")' <<<"$EMPTY_CONFIG")"
  cp "$bundle" "$layout/blobs/sha256/$(sha256sum "$bundle" | cut -d' ' -f1)"
  layer="$("$JQ" -cn --arg mt "$("$JQ" -r .mediaType "$bundle")" \
    --arg d "sha256:$(sha256sum "$bundle" | cut -d' ' -f1)" --argjson s "$(stat -c %s "$bundle")" \
    '{mediaType: $mt, digest: $d, size: $s}')"

  "$JQ" -cjn --argjson config "$EMPTY_CONFIG" --argjson layer "$layer" --argjson subject "$desc" \
    --arg type "$SLSA_PROVENANCE" '{
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: $layer.mediaType,
      config: $config,
      layers: [$layer],
      subject: $subject,
      annotations: {
        "dev.sigstore.bundle.content": "dsse-envelope",
        "dev.sigstore.bundle.predicateType": $type
      }
    }' >"$layout/manifest.json"
  manifest="sha256:$(sha256sum "$layout/manifest.json" | cut -d' ' -f1)"
  mv "$layout/manifest.json" "$layout/blobs/sha256/${manifest#sha256:}"
  "$JQ" -cn --arg d "$manifest" --argjson s "$(stat -c %s "$layout/blobs/sha256/${manifest#sha256:}")" \
    '{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $d, size: $s}]}' \
    >"$layout/index.json"

  if "$CRANE" manifest "$repo@$manifest" >/dev/null 2>&1; then
    echo "Provenance already attached to $repo@$("$JQ" -r .digest <<<"$desc")"
  else
    echo "Attaching the provenance to $repo@$("$JQ" -r .digest <<<"$desc") as $manifest"
    "$CRANE" push "$layout" "$repo@$manifest"
  fi
  rm -rf "$layout"
}

# The per-arch images are already in staging and signed there, so they are
# neither pushed nor signed here. They only get the provenance of the release
# attached, once every staging digest of the tagged commit is the attested one.
# The manifest list gets none: the image promoter verifies it through its
# platform manifests, and provenance about the manifest list would have to
# pass the policy on its own.

# Prints the "ARCH DIGEST" lines of the subjects of the image provenance,
# sorted. The subjects are named after the per-arch repositories.
image_subjects() {
  "$JQ" -r .dsseEnvelope.payload "$DIR/$IMAGE_BUNDLE" | base64 -d | "$JQ" -r --arg image "$IMAGE" '
    .subject[]
    | if (.name | test("^\($image)-[a-z0-9]+$")) and (.digest.sha256 // "" | test("^[a-f0-9]{64}$"))
      then "\(.name | ltrimstr("\($image)-")) sha256:\(.digest.sha256)"
      else error("unexpected subject \(.)") end' | sort
}

# Prints the tags Cloud Build gave the images of the tagged commit in a
# staging repository, see staging_commit_tags.
commit_tags() {
  local tags

  tags="$("$CRANE" ls "$1")" || return 1
  staging_commit_tags "$COMMIT" "$TAG" <<<"$tags"
}

# Checks that the staging images of the tagged commit and of the release
# version are the attested ones: the per-arch images, and the platform
# manifests of the manifest lists, which the image promoter verifies. Every
# build of the commit has to have pushed the same digests. Then
# fetches the per-arch manifests into the blobs of the layout $DIR/images and
# writes "ARCH DESCRIPTOR" lines to $DIR/images.descriptors.
check_images() {
  local subjects tags tag arch digest repo current file media_type desc failed=0
  local -a tag_list

  subjects="$(image_subjects)" || return 1
  echo "The provenance attests the per-arch images:"
  echo "$subjects"

  tags="$(commit_tags "$REGISTRY/$IMAGE")" || return 1
  if [[ -z "$tags" ]]; then
    echo "No staging image of $COMMIT in $REGISTRY/$IMAGE" >&2
    return 1
  fi
  mapfile -t tag_list <<<"$tags"
  for tag in "${tag_list[@]}" "$TAG"; do
    current="$("$CRANE" manifest "$REGISTRY/$IMAGE:$tag" | "$JQ" -r '
      if .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json" or
        .mediaType == "application/vnd.oci.image.index.v1+json"
      then .manifests[] else error("not a manifest list") end
      | if .platform.os == "linux" then "\(.platform.architecture) \(.digest)"
        else error("unexpected platform \(.platform)") end' | sort)" || return 1
    if [[ "$current" != "$subjects" ]]; then
      echo "The platforms of $REGISTRY/$IMAGE:$tag are not the attested images:" >&2
      echo "$current" >&2
      failed=1
    fi
  done

  while read -r arch digest; do
    repo="$REGISTRY/$IMAGE-$arch"
    tags="$(commit_tags "$repo")" || return 1
    if [[ -z "$tags" ]]; then
      echo "No staging image of $COMMIT in $repo" >&2
      failed=1
      continue
    fi
    mapfile -t tag_list <<<"$tags"
    for tag in "${tag_list[@]}" "$TAG"; do
      current="$("$CRANE" digest "$repo:$tag")" || return 1
      if [[ "$current" != "$digest" ]]; then
        echo "$repo:$tag is $current, but the provenance attests $digest" >&2
        failed=1
      fi
    done
  done <<<"$subjects"
  if [[ $failed -ne 0 ]]; then
    echo "The staging images of $COMMIT are not the ones the release attests" >&2
    return 1
  fi

  rm -rf "$DIR/images"
  mkdir -p "$DIR/images/blobs/sha256"
  : >"$DIR/images.descriptors"
  while read -r arch digest; do
    file="$DIR/images/blobs/sha256/${digest#sha256:}"
    "$CRANE" manifest "$REGISTRY/$IMAGE-$arch@$digest" >"$file" || return 1
    media_type="$("$JQ" -r .mediaType "$file")" || return 1
    if [[ "sha256:$(sha256sum "$file" | cut -d' ' -f1)" != "$digest" ]] ||
      [[ "$media_type" != application/vnd.docker.distribution.manifest.v2+json &&
        "$media_type" != application/vnd.oci.image.manifest.v1+json ]]; then
      echo "$REGISTRY/$IMAGE-$arch@$digest is no image manifest with that digest" >&2
      return 1
    fi
    desc="$("$JQ" -cn --arg mt "$media_type" --arg d "$digest" --argjson s "$(stat -c %s "$file")" \
      '{mediaType: $mt, digest: $d, size: $s}')" || return 1
    echo "$arch $desc" >>"$DIR/images.descriptors"
  done <<<"$subjects"
}

# Verifies the image provenance and attaches it to every per-arch image, in its
# own repository and as platform manifest in the repository of the manifest
# list, where container runtimes pull it and the image promoter verifies it.
# Writes the references to $DIR/images.refs.
publish_images() {
  local arch desc digest i
  local -a archs=() descs=() blobs=()

  check_images
  while read -r arch desc; do
    archs+=("$arch")
    descs+=("$desc")
    digest="$("$JQ" -r .digest <<<"$desc")"
    blobs+=("$DIR/images/blobs/sha256/${digest#sha256:}")
  done <"$DIR/images.descriptors"

  verify_provenance "$DIR/$IMAGE_BUNDLE" "$IMAGE_WORKFLOW" "${blobs[@]}"
  : >"$DIR/images.refs"
  for i in "${!descs[@]}"; do
    digest="$("$JQ" -r .digest <<<"${descs[$i]}")"
    attach_bundle "$REGISTRY/$IMAGE-${archs[$i]}" "${descs[$i]}" "$DIR/$IMAGE_BUNDLE"
    attach_bundle "$REGISTRY/$IMAGE" "${descs[$i]}" "$DIR/$IMAGE_BUNDLE"
    printf '%s\n' "$REGISTRY/$IMAGE-${archs[$i]}@$digest" "$REGISTRY/$IMAGE@$digest" >>"$DIR/images.refs"
  done
}

# Verifies that every per-arch image carries the provenance of the release as
# the image promoter finds it, like verify_published does for spoc and the
# chart. It only needs the GitHub identity, so it runs without signing too.
verify_images() {
  local ref failed=0

  echo "Verifying the provenance of the per-arch images by $SIGNER_WORKFLOW@refs/tags/$TAG"
  while read -r ref; do
    echo "Verifying $ref"
    check "SLSA provenance" github_provenance "$ref" "$IMAGE_WORKFLOW" || failed=1
  done <"$DIR/images.refs"

  if [[ $failed -ne 0 ]]; then
    echo "The per-arch images are missing their provenance, see the FAILED checks above" >&2
    return 1
  fi
  echo "All per-arch images carry their provenance"
}

# Waits for the image provenance, then checks the staging images, attaches the
# provenance and verifies it, see publish_images and verify_images. It runs
# after spoc and the chart are published, so that a late or failed image
# workflow only fails the job at the end.
images() {
  download_assets "$IMAGE_WAIT_TIMEOUT" "$IMAGE_BUNDLE"
  # The access token of the first login may have expired by now.
  if [[ -n "$LOGIN_REGISTRY" ]]; then
    registry_login "$LOGIN_REGISTRY"
  fi
  publish_images
  verify_images
}

# Signs manifests as the staging build, except the ones it signed already.
# Only cosign signatures count, bundles of the cosign sign predicate type, not
# any other bundle of the identity. A failed lookup fails rather than signing
# again.
sign_unsigned() {
  local ref status
  local -a unsigned=()

  for ref in "$@"; do
    status=1
    if signing_enabled && [[ -n "$SIGNER_IDENTITY" ]]; then
      status=0
      signed "$ref" || status=$?
    fi
    case "$status" in
    0) echo "Already signed: $ref" ;;
    1) unsigned+=("$ref") ;;
    *) return 1 ;;
    esac
  done

  if [[ ${#unsigned[@]} -gt 0 ]]; then
    "$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "${unsigned[@]}"
  fi
}

# Attests an SBOM as the staging build for each manifest, unless the manifest
# has an SBOM attestation of the build already that the jq condition accepts,
# with the SBOM as $sbom[0]. A failed lookup fails rather than attesting again.
attest_sbom() {
  local sbom="$1" condition="$2" ref statements
  shift 2

  if ! signing_enabled; then
    echo "Signing disabled, not attesting ${sbom##*/}"
    return 0
  fi
  for ref in "$@"; do
    if [[ -n "$SIGNER_IDENTITY" ]]; then
      statements="$(attestations "$ref" "$SPDX_DOCUMENT")" || return 1
      if [[ -n "$statements" ]] &&
        "$JQ" -se --slurpfile sbom "$sbom" "any(.[]; $condition)" <<<"$statements" >/dev/null; then
        echo "Already attested: ${sbom##*/} for $ref"
        continue
      fi
    fi
    attest "$ref" "$SPDX_DOCUMENT" "$sbom"
  done
}

# Verifies, pushes, attests and signs one artifact, and writes the references
# of its manifests to $DIR/NAME.refs. The files are verified as provenance
# subjects as well: the layout tar is none and could hold layers of its own
# instead, and the chart archive gets an SBOM.
publish() {
  local name="$1" repo="$2" tag="$3" bundle="$4" workflow="$5" tar="$6" desc digest
  local -a descs=() refs=() blobs=()
  shift 6

  # Not in a process substitution, whose failures would go unnoticed.
  unpack_layout "$name" "$tar" "$@" >"$DIR/$name.manifests"
  mapfile -t descs <"$DIR/$name.manifests"
  if ! "$JQ" -e --arg tag "$tag" '.annotations["org.opencontainers.image.version"] == $tag' \
    "$DIR/$name/blobs/sha256/$("$JQ" -r '.digest | ltrimstr("sha256:")' <<<"${descs[0]}")" >/dev/null; then
    echo "The $name manifest is not for version $tag" >&2
    return 1
  fi

  for desc in "${descs[@]}"; do
    digest="$("$JQ" -r .digest <<<"$desc")"
    refs+=("$repo@$digest")
    blobs+=("$DIR/$name/blobs/sha256/${digest#sha256:}")
  done
  verify_provenance "$DIR/$bundle" "$workflow" "${blobs[@]}" "${@/#/$DIR/}"
  push_layout "$DIR/$name" "$repo:$tag" "${descs[0]}"
  for desc in "${descs[@]}"; do
    attach_bundle "$repo" "$desc" "$DIR/$bundle"
  done
  sign_unsigned "${refs[@]}"
  printf '%s\n' "${refs[@]}" >"$DIR/$name.refs"
}

# The cosign signature of the staging build.
signature() {
  local status=0

  signed "$1" || status=$?
  if [[ $status -eq 1 ]]; then
    echo "no signature of $SIGNER_IDENTITY" >&2
  fi
  return "$status"
}

# The GitHub provenance of the release workflow about the digest, as the image
# promoter finds it: attached as referrer and signed by the provenance
# workflow of the tag.
github_provenance() {
  local ref="$1" workflow="$2" statements

  statements="$(SIGNER_IDENTITY="$SIGNER_WORKFLOW@refs/tags/$TAG" SIGNER_OIDC_ISSUER="$OIDC_ISSUER" \
    attestations "$ref" "$SLSA_PROVENANCE")" || return 1
  if [[ -z "$statements" ]]; then
    echo "no SLSA provenance of $SIGNER_WORKFLOW@refs/tags/$TAG" >&2
    return 1
  fi
  release_provenance "$workflow" <<<"$statements" || {
    echo "no SLSA provenance of $workflow at $TAG ($COMMIT) on GitHub hosted runners" >&2
    return 1
  }
}

# The SBOM attestations of the staging build about the digest: each of the
# given SBOMs, or any SBOM without one.
sboms() {
  local ref="$1" statements sbom
  shift

  statements="$(attestations "$ref" "$SPDX_DOCUMENT")" || return 1
  if [[ -z "$statements" ]]; then
    echo "no SPDX SBOM" >&2
    return 1
  fi
  for sbom in "$@"; do
    "$JQ" -se --slurpfile sbom "$sbom" 'any(.[]; .predicate == $sbom[0])' <<<"$statements" >/dev/null || {
      echo "no SBOM attestation of ${sbom##*/}" >&2
      return 1
    }
  done
}

# Verifies, like hack/verify-attestations.sh does for the staging build, that
# every manifest of an artifact carries the signature and the SBOMs of the
# staging build and the GitHub provenance of the release, so that a missing one
# fails this job rather than the promotion.
verify_published() {
  local name="$1" workflow="$2" ref failed=0 refs
  shift 2

  refs="$(cat "$DIR/$name.refs")"
  while read -r ref; do
    echo "Verifying $ref"
    check "signature" signature "$ref" || failed=1
    check "SLSA provenance" github_provenance "$ref" "$workflow" || failed=1
    check "SBOM" sboms "$ref" "$@" || failed=1
  done <<<"$refs"

  return "$failed"
}

download_assets "$WAIT_TIMEOUT" "${ASSETS[@]}"
if [[ -n "$LOGIN_REGISTRY" ]]; then
  registry_login "$LOGIN_REGISTRY"
fi

SPOC_WORKFLOW=.github/workflows/build.yml
CHART_WORKFLOW=.github/workflows/helm-chart-package.yaml

# The SBOMs of spoc are attested as they are, so they have to be the ones of
# the release.
verify_provenance "$DIR/spoc.intoto.jsonl" "$SPOC_WORKFLOW" "${SPOC_SBOMS[@]/#/$DIR/}"
publish spoc "$REGISTRY/spoc" "$TAG" spoc.intoto.jsonl \
  "$SPOC_WORKFLOW" spoc-oci-layout.tar "${SPOC_FILES[@]}"
mapfile -t SPOC_REFS <"$DIR/spoc.refs"
for sbom in "${SPOC_SBOMS[@]}"; do
  attest_sbom "$DIR/$sbom" '.predicate == $sbom[0]' "${SPOC_REFS[@]}"
done

publish chart "$REGISTRY/charts/$CHART" "$VERSION" "$CHART-$VERSION.intoto.jsonl" \
  "$CHART_WORKFLOW" "$CHART-$VERSION-oci-layout.tar" "${CHART_FILES[@]}"
CHART_REF="$(cat "$DIR/chart.refs")"
# Written like the SBOMs of the -dev charts, see hack/attest-artifact.sh. bom
# writes another SBOM every time, so any SBOM of the build counts.
if signing_enabled; then
  CHART_SBOM="$(artifact_sbom "$DIR/chart-sbom" "${CHART_REF##*/}" "$DIR/$CHART-$VERSION.tgz")"
  attest_sbom "$CHART_SBOM" true "$CHART_REF"
fi

failed=0
if ! signing_enabled; then
  echo "Signing disabled, not verifying the signatures and attestations"
elif [[ -z "$SIGNER_IDENTITY" ]]; then
  echo "WARNING: SIGNER_IDENTITY is not set, not verifying the signatures and attestations" >&2
else
  echo "Verifying the signatures and attestations by $SIGNER_IDENTITY and $SIGNER_WORKFLOW@refs/tags/$TAG"
  verify_published spoc "$SPOC_WORKFLOW" "${SPOC_SBOMS[@]/#/$DIR/}" || failed=1
  verify_published chart "$CHART_WORKFLOW" || failed=1
  if [[ $failed -ne 0 ]]; then
    echo "Signatures or attestations are missing, see the FAILED checks above" >&2
  else
    echo "All manifests carry their signature, provenance and SBOMs"
  fi
fi

# spoc and the chart are out, so a failure with the per-arch images only fails
# the job here, and a rerun of the job retries them. The subshell keeps
# errexit, which bash ignores in a function that runs as a condition.
set +e
(
  set -e
  images
)
images_status=$?
set -e
if [[ $images_status -ne 0 ]]; then
  echo "The per-arch images did not get their provenance, see doc/release.md#per-arch-images" >&2
  exit 1
fi
if [[ $failed -ne 0 ]]; then
  exit 1
fi
