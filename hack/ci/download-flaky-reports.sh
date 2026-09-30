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

set -euo pipefail

# Downloads the junit-flaky-* reports of the last completed runs of a workflow
# on a branch, one directory per run below DEST, and prints the directories
# which got reports, oldest first, for test/ci/junit-flakes.py. Runs without
# reports, like ones which skipped the e2e jobs or whose artifacts expired, are
# left out.
#
# Usage: download-flaky-reports.sh DEST WORKFLOW BRANCH EVENT LIMIT
#
# Needs GH_TOKEN with actions: read and GH_REPO.

DEST=$1
WORKFLOW=$2
BRANCH=$3
EVENT=$4
LIMIT=$5

mkdir -p "$DEST"

# gh lists the newest run first.
mapfile -t RUNS < <(
    gh run list \
        --workflow "$WORKFLOW" \
        --branch "$BRANCH" \
        --event "$EVENT" \
        --status completed \
        --limit "$LIMIT" \
        --json databaseId \
        --jq '.[].databaseId'
)

for ((i = ${#RUNS[@]} - 1; i >= 0; i--)); do
    run=${RUNS[i]}
    dir="$DEST/$run"
    if ! gh run download "$run" --pattern 'junit-flaky-*' --dir "$dir" >&2; then
        echo "No flaky test reports in run $run, skipping it" >&2
        continue
    fi
    if [[ -n "$(find "$dir" -name '*.xml' -print -quit)" ]]; then
        echo "$dir"
    fi
done
