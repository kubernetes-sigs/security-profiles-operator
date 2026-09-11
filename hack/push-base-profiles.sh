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

# Publishes the recorded runtime base profiles as OCI artifacts in the runtime
# format, which is what container runtimes consume for KEP-6061 `type: OCI`
# profiles and what the operator reads for oci:// base profiles since it
# recognizes the format by media type.
#
# The version comes from the profile itself, so a re-recorded profile is
# published under the runtime version it was recorded against.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
SPOC="${SPOC:-$BUILD_DIR/spoc}"
REGISTRY="${REGISTRY:-gcr.io/k8s-staging-sp-operator}"
# Keyless signing needs an OIDC identity. Publishing from a build system that
# has none, such as the staging Cloud Build job, has to turn it off.
SIGN="${SIGN:-true}"
# Identical content yields the same digest, so republishing is a no-op for the
# registry; what is already published is left alone to spare the pushes and
# the latest repoint. Set this to false to publish regardless.
SKIP_EXISTING="${SKIP_EXISTING:-true}"
EXAMPLES="${EXAMPLES:-examples}"
# Base profiles live under their own path, which keeps them apart from the test
# profiles and from anything else published under the same prefix. The profile
# object is still named after the last path segment, so an artifact at
# base/runc becomes a SeccompProfile called runc.
NAME_PREFIX="${NAME_PREFIX:-base/}"
if [[ $# -gt 0 ]]; then
  RUNTIMES=("$@")
else
  RUNTIMES=(runc crun)
fi

mkdir -p "$BUILD_DIR"

push_args=()
if [[ "$SIGN" != "true" ]]; then
  push_args+=(--disable-signing)
fi

published() {
  [[ "$SKIP_EXISTING" == "true" ]] || return 1

  "$SPOC" pull -s -o /dev/null "$1" >/dev/null 2>&1
}

# Whether a tag already serves this exact content, which is how latest is
# checked: it exists from the previous version too, so its presence says
# nothing about whether it still has to move.
serves() {
  local ref="$1" file="$2" pulled="$BUILD_DIR/published-check.json"

  [[ "$SKIP_EXISTING" == "true" ]] || return 1

  "$SPOC" pull -s -o "$pulled" "$ref" >/dev/null 2>&1 || return 1

  cmp -s "$pulled" "$file"
}

push() {
  local file="$1" ref="$2"

  echo "Publishing $file as $ref"
  "$SPOC" push ${push_args[@]+"${push_args[@]}"} -f "$file" "$ref"
}

for runtime in "${RUNTIMES[@]}"; do
  profile="$EXAMPLES/baseprofile-$runtime.yaml"
  # The profile is named after the runtime and the version it was recorded
  # against, for example runc-v1.5.1.
  version=$(sed -n "s/^  name: $runtime-//p" "$profile" | head -1)

  if [[ -z "$version" ]]; then
    echo "Unable to read the version from $profile." >&2
    echo "Expected a metadata name like $runtime-v1.2.3 indented by two spaces." >&2
    exit 1
  fi

  converted="$BUILD_DIR/baseprofile-$runtime.json"
  "$SPOC" convert -o "$converted" "$profile"

  # latest follows the newest recording for manual pulls; the tests derive the
  # versioned tag from the recorded profile. It moves only when a version is
  # published. It is deliberately never promoted: tags in registry.k8s.io cannot
  # be repointed, so a promoted latest would be frozen at whatever it pointed to
  # first.
  version_ref="$REGISTRY/$NAME_PREFIX$runtime:$version"
  latest_ref="$REGISTRY/$NAME_PREFIX$runtime:latest"

  if ! published "$version_ref"; then
    push "$converted" "$version_ref"
    push "$converted" "$latest_ref"
  elif ! serves "$latest_ref" "$converted"; then
    push "$converted" "$latest_ref"
  else
    echo "Already published, skipping $runtime $version"
  fi
done
