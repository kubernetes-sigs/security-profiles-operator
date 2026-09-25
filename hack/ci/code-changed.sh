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

# Writes code=false to the GitHub step output for a pull request which only
# changes documentation, and code=true otherwise, so that workflows can skip
# their builds and tests for documentation changes. Workflows gate the jobs
# with `if:` instead of skipping the whole workflow with `paths-ignore`, because
# a skipped job still reports a check run for required checks, while a skipped
# workflow reports none and leaves the pull request waiting.
#
# Pull request checkouts are merge commits, so the first parent is the base
# branch. Everything that is not a pull request always counts as code.

set -euo pipefail

code=true
if [[ "${EVENT_NAME:-}" == "pull_request" ]]; then
    code=false
    while IFS= read -r file; do
        case "$file" in
        *.md | doc/* | LICENSE | OWNERS | OWNERS_ALIASES | SECURITY_CONTACTS) ;;
        *)
            code=true
            break
            ;;
        esac
    done < <(git diff --name-only HEAD^1 HEAD)
fi

echo "Code changed: $code"
echo "code=$code" >>"${GITHUB_OUTPUT:-/dev/stdout}"
