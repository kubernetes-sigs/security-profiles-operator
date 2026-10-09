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

# Writes code and build-image to the GitHub step output, so that workflows can
# skip the jobs whose inputs did not change. Workflows gate the jobs with `if:`
# instead of skipping the whole workflow with `paths-ignore`, because a skipped
# job still reports a check run for required checks, while a skipped workflow
# reports none and leaves the pull request waiting.
#
# code is false for a pull request which only changes documentation, and for
# scheduled and manual runs, which change nothing: the build workflow only
# rebuilds the toolchain image then, the codeql workflow runs its analysis
# regardless. Everything else always counts as code.
#
# build-image is true when a pull request or a push changes an input of the
# toolchain image of Dockerfile.build-image, see build-image-inputs.sh, and for
# scheduled and manual runs. Releases never rebuild it.
#
# Pull request checkouts are merge commits, so the first parent is the base
# branch. A push gets compared with BEFORE, the previous head of the branch.

set -euo pipefail

# shellcheck source=hack/ci/build-image-inputs.sh
source "$(dirname "${BASH_SOURCE[0]}")/build-image-inputs.sh"

code=true
build_image=false
case "${EVENT_NAME:-}" in
pull_request)
    files="$(git diff --name-only HEAD^1 HEAD)"
    code=false
    while IFS= read -r file; do
        case "$file" in
        "" | *.md | doc/* | LICENSE | OWNERS | OWNERS_ALIASES | SECURITY_CONTACTS) ;;
        *)
            code=true
            break
            ;;
        esac
    done <<<"$files"
    if grep -E "$BUILD_IMAGE_INPUTS" <<<"$files" >/dev/null; then
        build_image=true
    fi
    ;;
push)
    # A new branch, or a previous head which a force push removed, leaves
    # nothing to compare with.
    build_image=true
    if [[ -n "${BEFORE:-}" && ! "$BEFORE" =~ ^0+$ ]] &&
        { git cat-file -e "$BEFORE^{commit}" 2>/dev/null ||
            git fetch --no-tags --depth=1 origin "$BEFORE"; } &&
        files="$(git diff --name-only "$BEFORE" HEAD)" &&
        ! grep -E "$BUILD_IMAGE_INPUTS" <<<"$files" >/dev/null; then
        build_image=false
    fi
    ;;
schedule | workflow_dispatch)
    code=false
    build_image=true
    ;;
esac

echo "Code changed: $code"
echo "Toolchain image inputs changed: $build_image"
{
    echo "code=$code"
    echo "build-image=$build_image"
} >>"${GITHUB_OUTPUT:-/dev/stdout}"
