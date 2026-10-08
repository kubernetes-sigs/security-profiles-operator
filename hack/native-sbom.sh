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

# Writes an SPDX 3 SBOM of the C libraries the binaries of the given flake
# packages link statically, for example spoc-amd64. The Go SBOMs only list Go
# modules, because bom reads them from the build information of the binaries,
# which knows nothing about libseccomp, libbpf and the other native libraries.
# nix knows exactly which versions went into the build, so they come from the
# build inputs of the derivations.
#
# Usage: hack/native-sbom.sh NAME OUTPUT PACKAGE...

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 NAME OUTPUT PACKAGE..." >&2
  exit 1
fi

NAME="$1"
OUTPUT="$2"
shift 2

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Only evaluates, but the flake inputs must not come from anywhere else than
# for the build.
NIX=(nix --extra-experimental-features 'nix-command flakes'
  --option substituters https://cache.nixos.org)

# The name, version and source URL of every build input, which are the
# libraries the Makefile links.
LIBRARIES='d: map (p: {
  name = p.pname or (builtins.parseDrvName p.name).name;
  version = p.version or "";
  url = let s = p.src or null; in
    if s == null then "NOASSERTION"
    else s.url or (builtins.head (s.urls or [ "NOASSERTION" ]));
}) d.buildInputs'

packages="[]"
for pkg in "$@"; do
  libs=$("${NIX[@]}" eval --json "path:$ROOT#$pkg" --apply "$LIBRARIES")
  # Outputs of the same library, like glibc and glibc.static, are one package.
  # nix mirror:// URLs are no download locations for anybody else.
  packages=$(jq -n --argjson a "$packages" --argjson b "$libs" '
    $a + $b
    | map(if .url | startswith("mirror://") then .url = "NOASSERTION" else . end)
    | group_by([.name, .version])
    | map(sort_by(.url == "NOASSERTION") | .[0])')
done

NIXPKGS_REV=$(jq -er '.nodes.nixpkgs.locked.rev' "$ROOT/flake.lock")

# The namespace has to be unique per document: the packages it was generated
# for and their content identify it.
DOCUMENT_ID=$(printf '%s\n%s\n' "$*" "$packages" | sha256sum | cut -d' ' -f1)

if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  CREATED=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
  CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi

# The IDs of the elements are IRIs in the namespace of the document. Only the
# blank node of the creation info is local.
jq -n \
  --arg name "$NAME" \
  --arg created "$CREATED" \
  --arg nixpkgs "$NIXPKGS_REV" \
  --arg document "https://github.com/kubernetes-sigs/security-profiles-operator/spdx/$NAME/$NIXPKGS_REV/$DOCUMENT_ID" \
  --argjson packages "$packages" \
  'def id($kind): "\($document)#\($kind)";
  def package_id: id("Package-\(.name)-\(.version)" | gsub("[^A-Za-z0-9.-]"; "-"));
  {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": ([
      {
        type: "CreationInfo",
        "@id": "_:creationinfo",
        specVersion: "3.0.1",
        created: $created,
        createdBy: [id("organization")],
        createdUsing: [id("tool")]
      },
      {
        type: "Organization",
        spdxId: id("organization"),
        creationInfo: "_:creationinfo",
        name: "Kubernetes Security Profiles Operator"
      },
      {
        type: "Tool",
        spdxId: id("tool"),
        creationInfo: "_:creationinfo",
        name: "hack/native-sbom.sh"
      },
      {
        type: "SpdxDocument",
        spdxId: $document,
        creationInfo: "_:creationinfo",
        name: $name,
        profileConformance: ["core", "software"],
        rootElement: [id("sbom")]
      },
      {
        type: "software_Sbom",
        spdxId: id("sbom"),
        creationInfo: "_:creationinfo",
        software_sbomType: ["build"],
        rootElement: [$packages[] | package_id]
      }
    ] + [
      $packages[] | {
        type: "software_Package",
        spdxId: package_id,
        creationInfo: "_:creationinfo",
        name: .name,
        software_packageVersion: .version,
        software_primaryPurpose: "library",
        software_sourceInfo: "built from nixpkgs \($nixpkgs)"
      } + if .url == "NOASSERTION" then {} else {software_downloadLocation: .url} end
    ])
  }' >"$OUTPUT"
