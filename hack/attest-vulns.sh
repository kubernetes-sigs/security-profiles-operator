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

# Scans the binaries of each given image digest with govulncheck and attests
# the result twice: as vulnerability scan
# (https://in-toto.io/attestation/vulns/v0.2) and as OpenVEX document
# (https://openvex.dev/ns), which marks vulnerabilities as affected only if the
# binaries use the vulnerable symbols. A clean scan has an empty result and no
# VEX document, because an OpenVEX document needs at least one statement. The Go
# vulnerability database has no severity scores, so the scan results carry
# none.

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

BINARIES=(security-profiles-operator spoc)

if ! signing_enabled; then
  echo "Signing disabled, not attesting vulnerability scans: $*"
  exit 0
fi

for ref in "$@"; do
  require_digest "$ref"
done

# govulncheck reports findings with exit code 0 in the JSON and OpenVEX
# formats, but documents exit code 3 for them as well.
scan() {
  local status=0

  "$(govulncheck_bin)" -mode binary "$@" || status=$?
  if [[ $status -ne 0 && $status -ne 3 ]]; then
    echo "govulncheck failed with exit code $status" >&2
    return "$status"
  fi
}

mkdir -p "$BUILD_DIR/attestations"

for ref in "$@"; do
  name="$(image_name "$ref")"
  binaries="$(extract_binaries "$ref")"
  scans="$BUILD_DIR/attestations/$name.scans"
  mkdir -p "$scans"

  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for binary in "${BINARIES[@]}"; do
    echo "Scanning $binary of $ref"
    scan -format openvex "$binaries/$binary" >"$scans/$binary.openvex.json"
    scan -format json "$binaries/$binary" >"$scans/$binary.govulncheck.json"
  done
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # One statement per vulnerability for the image. A vulnerability counts as
  # affected if any binary uses it, the affected modules are kept as
  # subcomponents.
  vex="$BUILD_DIR/attestations/$name.openvex.json"
  "$(jq_bin)" -s \
    --arg id "https://console.cloud.google.com/cloud-build/builds/${BUILD_ID:-local}#$name-vex" \
    --arg author "$REPOSITORY_URL/blob/main/hack/attest-vulns.sh" \
    --arg timestamp "$finished" \
    --arg product "$(image_purl "$ref")" \
    '{
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": $id,
      author: $author,
      timestamp: $timestamp,
      version: 1,
      statements: (
        [.[] | (.statements // [])[]]
        | group_by(.vulnerability.name)
        | map(
            ((map(select(.status == "affected")) + .)[0].status) as $status
            | map(select(.status == $status))
            | .[0] + {products: [{
                "@id": $product,
                subcomponents: ([.[].products[].subcomponents[]?] | unique)
              }]}
          )
      )
    }' "$scans"/*.openvex.json >"$vex"
  if [[ "$("$(jq_bin)" '.statements | length' "$vex")" -gt 0 ]]; then
    attest "$ref" https://openvex.dev/ns "$vex"
  else
    echo "No vulnerabilities found, no VEX document for $ref"
  fi

  # govulncheck writes a stream of JSON messages per binary.
  vulns="$BUILD_DIR/attestations/$name.vulns.json"
  "$(jq_bin)" -s \
    --arg started "$started" \
    --arg finished "$finished" \
    '(map(select(.config)) | first | .config) as $config
    | (map(select(.osv)) | map({key: .osv.id, value: (.osv.aliases // [])}) | from_entries) as $aliases
    | {
        scanner: {
          uri: "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
          version: $config.scanner_version,
          db: {uri: $config.db, lastUpdate: $config.db_last_modified},
          result: (
            [.[] | select(.finding) | .finding.osv]
            | unique
            | map(
                {id: ., severity: []}
                + if ($aliases[.] // []) == [] then {} else {annotations: [{aliases: $aliases[.]}]} end
              )
          )
        },
        metadata: {scanStartedOn: $started, scanFinishedOn: $finished}
      }' "$scans"/*.govulncheck.json >"$vulns"
  attest "$ref" https://in-toto.io/attestation/vulns/v0.2 "$vulns"
done
