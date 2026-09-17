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

# Signs the given image references keylessly by digest. The signatures are
# Sigstore bundles attached as OCI referrers. The identity comes from the
# ambient credentials, for example the metadata server in Cloud Build.
# SIGN=false skips signing.

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

if ! signing_enabled; then
  echo "Signing disabled, not signing: $*"
  exit 0
fi

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 IMAGE:TAG|IMAGE@DIGEST..." >&2
  exit 1
fi

COSIGN="$(cosign_bin)"

# All tags of an image point to the same digest, so signing one reference
# per image is enough. References that already contain a digest, for example
# OCI artifacts like helm charts, are signed as given.
sign() {
  local target

  target="$(resolve_digest "$1")"
  echo "Signing $target"
  "$COSIGN" sign --yes --use-signing-config "$target"
}

parallel_each sign "$@"
