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

# Wraps the spoc binaries and the Helm chart archive of a build into OCI image
# layouts, which hack/push-release-artifacts.sh pushes to the staging registry
# byte for byte, see doc/release.md#oci-artifacts. The manifests only depend on
# the wrapped files, the version, the commit and its time, so a build always
# writes the same manifests for the same files. The digests of the manifests
# are printed in the format of sha256sum, for the provenance subjects.
#
#   oci-layout.sh spoc LAYOUT FILE:ARCH...
#     An index with one manifest per binary. Each binary is the only layer of
#     its manifest, uncompressed, so the layer digest is the sha256 of the
#     binary.
#
#   oci-layout.sh chart LAYOUT CHART_TGZ
#     The chart archive as helm pushes it, with its modification time set to
#     the commit time, which helm uses as creation time. The manifest depends
#     on the helm version as well, the workflow pins it.
#
#   oci-layout.sh pack LAYOUT TAR
#     Writes the layout without the layer blobs to TAR. The layers are the
#     release assets, so the release only carries the manifests once more.

set -euo pipefail

REPOSITORY_URL=https://github.com/kubernetes-sigs/security-profiles-operator
SPOC_ARTIFACT_TYPE=application/vnd.k8s.security-profiles-operator.spoc.v1
SHA512_ANNOTATION=io.k8s.security-profiles-operator.sha512
SPOC_SUBJECT="${SPOC_SUBJECT:-registry.k8s.io/security-profiles-operator/spoc}"
CHART_SUBJECT="${CHART_SUBJECT:-registry.k8s.io/security-profiles-operator/charts/security-profiles-operator}"
HELM="${HELM:-helm}"
CRANE="${CRANE:-crane}"

EMPTY_CONFIG='{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2}'

usage() {
  sed -n '/^#   oci-layout.sh/,/^$/p' "${BASH_SOURCE[0]}" >&2
  exit 1
}

# The commit, its time and the version default to the checked out commit.
REVISION="${REVISION:-$(git rev-parse HEAD)}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct "$REVISION")}"
CREATED="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"

# Fails if the layout exists, nothing gets added to an existing one.
layout_new() {
  if [[ -e "$1" ]]; then
    echo "$1 exists already" >&2
    return 1
  fi
}

# Starts an empty layout.
layout_init() {
  local layout="$1"

  layout_new "$layout"
  mkdir -p "$layout/blobs/sha256"
  printf '{"imageLayoutVersion":"1.0.0"}' >"$layout/oci-layout"
}

# Copies a file into the blobs of a layout and prints its descriptor.
blob_file() {
  local layout="$1" file="$2" media_type="$3" hex size

  hex="$(sha256sum "$file" | cut -d' ' -f1)"
  size="$(stat -c %s "$file")"
  cp "$file" "$layout/blobs/sha256/$hex"
  jq -cn --arg mt "$media_type" --arg d "sha256:$hex" --argjson s "$size" \
    '{mediaType: $mt, digest: $d, size: $s}'
}

# Writes JSON from stdin as a blob and prints its descriptor, without a
# trailing newline so that the digest covers the JSON only.
blob_json() {
  local layout="$1" media_type="$2" tmp desc

  tmp="$(mktemp "$layout/blob.XXXXXX")"
  jq -cj . >"$tmp"
  desc="$(blob_file "$layout" "$tmp" "$media_type")"
  rm -f "$tmp"
  echo "$desc"
}

# Writes the index.json of a layout with a single descriptor.
layout_index() {
  local layout="$1" desc="$2"

  jq -cn --argjson desc "$desc" \
    '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: [$desc]}' \
    >"$layout/index.json"
}

# Prints a sha256sum line for the digest of a descriptor.
subject() {
  local desc="$1" name="$2"

  echo "$(jq -r '.digest | ltrimstr("sha256:")' <<<"$desc")  $name"
}

spoc() {
  local layout="$1" version annotations arg file arch layer manifest desc
  local -a manifests=()
  shift
  [[ $# -gt 0 ]] || usage

  version="${VERSION:-v$(cat VERSION)}"
  layout_init "$layout"
  printf '{}' >"$layout/blobs/sha256/$(jq -r '.digest | ltrimstr("sha256:")' <<<"$EMPTY_CONFIG")"

  annotations="$(jq -cn --arg created "$CREATED" --arg revision "$REVISION" \
    --arg source "$REPOSITORY_URL" --arg version "$version" '{
      "org.opencontainers.image.created": $created,
      "org.opencontainers.image.revision": $revision,
      "org.opencontainers.image.source": $source,
      "org.opencontainers.image.version": $version
    }')"

  for arg in "$@"; do
    file="${arg%:*}"
    arch="${arg##*:}"
    if [[ "$file" == "$arg" || -z "$arch" || ! -f "$file" ]]; then
      echo "Expected FILE:ARCH of an existing file, got $arg" >&2
      return 1
    fi

    layer="$(blob_file "$layout" "$file" application/octet-stream |
      jq -c --arg sha512 "$(sha512sum "$file" | cut -d' ' -f1)" --arg key "$SHA512_ANNOTATION" \
        '. + {annotations: {"org.opencontainers.image.title": "spoc", ($key): $sha512}}')"
    manifest="$(jq -cn --arg at "$SPOC_ARTIFACT_TYPE" --argjson config "$EMPTY_CONFIG" \
      --argjson layer "$layer" --argjson annotations "$annotations" '{
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        artifactType: $at,
        config: $config,
        layers: [$layer],
        annotations: $annotations
      }' | blob_json "$layout" application/vnd.oci.image.manifest.v1+json)"
    subject "$manifest" "$SPOC_SUBJECT"
    manifests+=("$(jq -c --arg at "$SPOC_ARTIFACT_TYPE" --arg arch "$arch" \
      '. + {artifactType: $at, platform: {architecture: $arch, os: "linux"}}' <<<"$manifest")")
  done

  desc="$(printf '%s\n' "${manifests[@]}" | jq -cs --arg at "$SPOC_ARTIFACT_TYPE" \
    --argjson annotations "$annotations" '{
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      artifactType: $at,
      manifests: .,
      annotations: $annotations
    }' | blob_json "$layout" application/vnd.oci.image.index.v1+json)"
  subject "$desc" "$SPOC_SUBJECT"
  layout_index "$layout" "$desc"
}

# helm writes the chart manifest itself, pushing it to a registry which only
# lives in this process.
chart() {
  local layout="$1" tgz="$2" dir log port version pid digest
  [[ -f "$tgz" ]] || usage
  layout_new "$layout"

  dir="$(mktemp -d)"
  log="$dir/registry.log"
  "$CRANE" registry serve --address 127.0.0.1:0 >"$log" 2>&1 &
  pid=$!
  # shellcheck disable=SC2064
  trap "kill $pid 2>/dev/null; rm -rf '$dir'" EXIT

  for _ in $(seq 50); do
    port="$(sed -n 's/.*serving on port \([0-9]*\).*/\1/p' "$log")"
    [[ -n "$port" ]] && break
    sleep 0.1
  done
  if [[ -z "$port" ]]; then
    echo "The local registry did not start:" >&2
    cat "$log" >&2
    return 1
  fi

  cp "$tgz" "$dir/chart.tgz"
  touch -d "@$SOURCE_DATE_EPOCH" "$dir/chart.tgz"
  version="$("$HELM" show chart "$dir/chart.tgz" | sed -n 's/^version: *//p')"
  TZ=UTC "$HELM" push --plain-http "$dir/chart.tgz" "oci://127.0.0.1:$port/charts" >&2

  digest="$("$CRANE" digest --insecure "127.0.0.1:$port/charts/security-profiles-operator:$version")"
  "$CRANE" pull --insecure --format oci \
    "127.0.0.1:$port/charts/security-profiles-operator@$digest" "$layout"
  echo "${digest#sha256:}  $CHART_SUBJECT"
}

# The digests of the layers of all manifests in a layout.
layer_digests() {
  local layout="$1" blob

  for blob in "$layout"/blobs/sha256/*; do
    # Manifests are small JSON documents, layers can be large binaries.
    [[ "$(stat -c %s "$blob")" -lt 1048576 ]] || continue
    jq -r 'select(type == "object" and has("layers")) | .layers[].digest' "$blob" 2>/dev/null || true
  done | sort -u
}

pack() {
  local layout="$1" tar="$2" digest
  local -a exclude=()

  [[ -f "$layout/index.json" ]] || usage
  while read -r digest; do
    exclude+=("--exclude=./blobs/sha256/${digest#sha256:}")
  done < <(layer_digests "$layout")

  tar --sort=name --owner=0 --group=0 --numeric-owner --mode=u=rwX,go=rX --mtime="@$SOURCE_DATE_EPOCH" \
    "${exclude[@]}" -C "$layout" -cf "$tar" .
}

[[ $# -ge 2 ]] || usage
command="$1"
shift
case "$command" in
spoc | chart | pack) "$command" "$@" ;;
*) usage ;;
esac
