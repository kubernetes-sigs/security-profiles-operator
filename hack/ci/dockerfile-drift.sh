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

# Fails when the final stages of Dockerfile and Dockerfile.ubi drift apart in
# what users of the image see: the label keys and values, the user and the
# name of the entrypoint binary. The base images and the binary paths differ
# on purpose.

set -euo pipefail

REFERENCE="${1:-Dockerfile}"
OTHERS=("${@:2}")
if [[ ${#OTHERS[@]} -eq 0 ]]; then
  OTHERS=(Dockerfile.ubi)
fi

# Prints the instructions of the final stage, one per line with the
# continuation lines joined and comments dropped.
final_stage() {
  awk '
    /^[[:space:]]*#/ { next }
    {
      line = line $0
      if (line ~ /\\$/) { sub(/\\$/, " ", line); next }
      print line
      line = ""
    }
  ' "$1" | awk 'toupper($1) == "FROM" { stage = "" } { stage = stage $0 "\n" } END { printf "%s", stage }'
}

# The LABEL key=value pairs of the final stage, sorted.
labels() {
  final_stage "$1" | grep -E '^[[:space:]]*LABEL[[:space:]]' |
    sed -E 's/^[[:space:]]*LABEL[[:space:]]+//' |
    grep -oE '[A-Za-z0-9_.-]+=("[^"]*"|[^[:space:]]+)' | sort
}

user() {
  final_stage "$1" | awk 'toupper($1) == "USER" { user = $2 } END { print user }'
}

entrypoint() {
  final_stage "$1" | awk 'toupper($1) == "ENTRYPOINT" { e = $0 } END { print e }' |
    grep -oE '"[^"]+"' | head -1 | tr -d '"' | xargs -r basename
}

failed=0
check() {
  local what="$1" file="$2" expected="$3" actual="$4"

  if [[ "$expected" != "$actual" ]]; then
    echo "$file drifted from $REFERENCE in its $what:" >&2
    diff <(echo "$expected") <(echo "$actual") >&2 || true
    failed=1
  fi
}

for file in "${OTHERS[@]}"; do
  check labels "$file" "$(labels "$REFERENCE")" "$(labels "$file")"
  check user "$file" "$(user "$REFERENCE")" "$(user "$file")"
  check entrypoint "$file" "$(entrypoint "$REFERENCE")" "$(entrypoint "$file")"
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
echo "${OTHERS[*]} match $REFERENCE"
