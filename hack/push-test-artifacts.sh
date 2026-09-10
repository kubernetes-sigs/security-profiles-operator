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

# Pushes the seccomp profiles used by the Kubernetes e2e_node tests for
# KEP-6061 as OCI artifacts. The artifacts are pushed unsigned because build
# systems have no OIDC identity, and are promoted to registry.k8s.io from the
# staging registry afterwards.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
SPOC="${SPOC:-$BUILD_DIR/spoc}"
REGISTRY="${REGISTRY:-gcr.io/k8s-staging-sp-operator}"
REPOSITORY="${REPOSITORY:-seccomp-test-profiles}"
EXAMPLES="${EXAMPLES:-examples/test-profiles}"

# Larger than the 1 MiB an artifact may have by default, to test the runtime
# size limit. Generated rather than committed to keep the repository small.
oversized="$BUILD_DIR/oversized.json"
mkdir -p "$BUILD_DIR"
{
  printf '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"action":"SCMP_ACT_ERRNO","names":['
  for i in $(seq 1 60000); do
    if [[ $i -gt 1 ]]; then printf ','; fi
    printf '"syscall_that_does_not_exist_%d"' "$i"
  done
  printf ']}]}'
} > "$oversized"

SKIP_EXISTING="${SKIP_EXISTING:-true}"

push() {
  local file="$1" ref="$REGISTRY/$REPOSITORY:$2"

  if [[ "$SKIP_EXISTING" == "true" ]] &&
      "$SPOC" pull -s -o /dev/null "$ref" >/dev/null 2>&1; then
    echo "Already published, skipping $ref"

    return
  fi

  echo "Pushing $file as $ref"
  "$SPOC" push --disable-signing -f "$file" "$ref"
}

push "$EXAMPLES/deny-chmod.json" deny-chmod
push "$EXAMPLES/permissive.json" permissive
push "$EXAMPLES/invalid.json" invalid
push "$oversized" oversized

echo
echo "Add the digests logged above to images.yaml in kubernetes/k8s.io under"
echo "registry.k8s.io/images/k8s-staging-sp-operator to promote them."
