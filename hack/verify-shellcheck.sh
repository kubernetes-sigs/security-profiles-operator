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

# Runs shellcheck on every tracked shell script outside of vendor: the *.sh
# files and the files with a bash or sh shebang or a shellcheck shell
# directive. Sourced files get followed, relative to the repository root.

set -euo pipefail

SHELLCHECK="${SHELLCHECK:-shellcheck}"

cd "$(git rev-parse --show-toplevel)"

scripts=()
while IFS= read -r -d '' file; do
  [[ -f "$file" ]] || continue
  if [[ "$file" == *.sh ]] ||
    head -n 1 "$file" | grep -qE '^#!.*[/ ](bash|sh)([[:space:]]|$)' ||
    head -n 20 "$file" | grep -q '^# shellcheck shell='; then
    scripts+=("$file")
  fi
done < <(git ls-files -z --cached --others --exclude-standard -- . ':!:vendor' ':!:*.go' ':!:*.md' ':!:*.yaml' ':!:*.json')

echo "Checking ${#scripts[@]} shell scripts with $("$SHELLCHECK" --version | sed -n 's/^version: //p')"
"$SHELLCHECK" --external-sources --source-path=SCRIPTDIR "${scripts[@]}"
