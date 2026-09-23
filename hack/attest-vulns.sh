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
#
# Maintainers assess findings in the OpenVEX document .openvex.json. Its
# statement replaces the assessment of a found vulnerability with the same name
# when one of its products is the image purl without version. A not_affected
# statement needs a justification or an impact statement. Statements claiming
# that the vulnerable code or component is not present are ignored with a
# warning when govulncheck observes the vulnerable symbols, because the claim is
# outdated then. Affected statements without an action statement name the
# module, the fixed version if there is one, and the vulnerability entry.
#
# Symbols are only observed when the binary carries a symbol table. Without one
# govulncheck falls back to module level and reports the packages and symbols of
# the advisory instead of the ones in the binary, with a wildcard in place of
# the symbol name. Those findings say that a vulnerable module is present, not
# that its code is, so they never invalidate an assessment. The binaries are
# built without -s for this reason, see LDFLAGS in the Makefile.

# jq programs are single quoted on purpose
# shellcheck disable=SC2016
set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

BINARIES=(security-profiles-operator spoc)
VEX_FILE="${VEX_FILE:-$(dirname "${BASH_SOURCE[0]}")/../.openvex.json}"

if ! signing_enabled; then
  echo "Signing disabled, not attesting vulnerability scans: $*"
  exit 0
fi

for ref in "$@"; do
  require_digest "$ref"
done

if ! "$(jq_bin)" -e '
    .statements | all(
      (.vulnerability.name | type == "string")
      and ((.products // []) | length > 0)
      and (.status | IN("not_affected", "affected", "fixed", "under_investigation"))
      and (.status != "not_affected" or .justification != null or .impact_statement != null)
    )' "$VEX_FILE" >/dev/null; then
  echo "Invalid statements in $VEX_FILE" >&2
  exit 1
fi

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
  # subcomponents. A maintained statement replaces the assessment.
  cat "$scans"/*.govulncheck.json >"$scans/findings.json"

  # Vulnerabilities whose symbols govulncheck actually saw in the binaries. A
  # trace without a concrete function is a module or package level finding.
  observed=$("$(jq_bin)" -s \
    '[.[] | .finding? | select(.trace[0].function? // "" | test("\\*$") | not)
      | select(.trace[0].function != null) | .osv] | unique' "$scans/findings.json")

  wildcards=$("$(jq_bin)" -s \
    '[.[] | .finding? | select(.trace[0].function? // "" | test("\\*$"))] | length' \
    "$scans/findings.json")
  if [[ "$wildcards" -gt 0 ]]; then
    echo "WARNING: binaries of $ref have no symbol table, govulncheck can only report which vulnerable modules they contain" >&2
  fi

  outdated=$("$(jq_bin)" -rs \
    --slurpfile assessments "$VEX_FILE" \
    --argjson observed "$observed" \
    --arg genericProduct "pkg:oci/$name" \
    '[.[] | (.statements // [])[] | select(.status == "affected") | .vulnerability.name]
    | unique[] as $found
    | select($found | IN($observed[]))
    | $assessments[0].statements[]
    | select(.vulnerability.name == $found
        and any(.products[]; ."@id" == $genericProduct)
        and (.justification | IN("vulnerable_code_not_present", "component_not_present")))
    | $found' "$scans"/*.openvex.json)
  for vulnerability in $outdated; do
    echo "WARNING: govulncheck observes $vulnerability in $ref, ignoring its outdated assessment in $VEX_FILE" >&2
  done

  vex="$BUILD_DIR/attestations/$name.openvex.json"
  "$(jq_bin)" -s \
    --slurpfile assessments "$VEX_FILE" \
    --slurpfile findings "$scans/findings.json" \
    --argjson observed "$observed" \
    --arg genericProduct "pkg:oci/$name" \
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
            | .vulnerability.name as $name
            | ($assessments[0].statements
                | map(select(.vulnerability.name == $name
                    and any(.products[]; ."@id" == $genericProduct)))
                | last) as $assessment
            | if $assessment != null
                and (.status != "affected"
                  or ($assessment.justification
                    | IN("vulnerable_code_not_present", "component_not_present")
                    | not)
                  or ($name | IN($observed[]) | not))
              then
                del(.status, .justification, .impact_statement, .action_statement)
                + ($assessment | del(.vulnerability, .products, .timestamp, .last_updated))
              elif .status == "affected" and .action_statement == null then
                ([$findings[] | .finding? | select(.osv == $name)] | first) as $finding
                | ($finding.trace[0].module // "the affected module") as $module
                | .action_statement = (
                    if ($finding.fixed_version // null) == null then
                      "No fixed version of \($module) is available, see \(.vulnerability."@id" // $name)."
                    else
                      "Update \($module) to \($finding.fixed_version) or later, see \(.vulnerability."@id" // $name)."
                    end
                  )
              else .
              end
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
