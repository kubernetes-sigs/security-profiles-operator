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

# Waits until the job JOB of the current workflow run uploaded the artifact
# NAME, so that a job which only needs the artifact late can start without
# needs: on JOB, like an e2e VM which boots while the image job builds the
# image. needs: on a matrix job also waits for all of its other jobs. It fails
# once JOB completed without uploading the artifact, and gives up after an
# hour.
#
# It watches the step named STEP of the latest attempt of JOB, which uploads
# the artifact, and only lists the artifacts once that step or JOB completed.
# Without STEP or without a step of that name, it waits for JOB to complete.
# A rerun of the failed jobs keeps the completed JOB of the earlier attempt
# with its artifact, a rerun of all jobs waits for the upload of the new
# attempt.
#
# Usage: hack/ci/wait-for-artifact.sh NAME JOB [STEP]
#
# Needs GH_TOKEN with actions: read, GITHUB_REPOSITORY and GITHUB_RUN_ID.

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 NAME JOB [STEP]" >&2
  exit 2
fi

NAME=$1
JOB=$2
STEP=${3:-}

# The requests of all jobs of the repository share the rate limit of
# GITHUB_TOKEN, every poll makes one.
INTERVAL=60
TIMEOUT=3600

RUN="repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"

# The state of JOB and of STEP, like "in_progress completed success", "none"
# for a step or a job which is not there (yet).
# shellcheck disable=SC2016 # $step is a jq variable
STATE='[.jobs[] | select(.name == "'"$JOB"'")][0] |
  if . == null then "none" else
    ([.steps[]? | select(.name == "'"$STEP"'")][0]) as $step |
    "\(.status) \($step.status // "none") \($step.conclusion // "none")"
  end'

# The rate limit which applies to the polls. Requests of the rate_limit
# endpoint do not count against it.
if limit=$(gh api rate_limit --jq '.resources.core | "\(.used) of \(.limit) requests per hour used"'); then
  echo "Rate limit of GITHUB_TOKEN: $limit"
fi

deadline=$((SECONDS + TIMEOUT))
while true; do
  # A failed request, like one over the rate limit, gets retried.
  if ! state=$(gh api "$RUN/jobs?per_page=100" --jq "$STATE"); then
    echo "Unable to list the jobs of the run, retrying"
  else
    read -r job_status step_status _ <<<"$state"

    if [[ "$job_status" == completed || "$step_status" == completed ]]; then
      if ! count=$(gh api "$RUN/artifacts?name=$NAME&per_page=100" \
        --jq '[.artifacts[] | select(.expired | not)] | length'); then
        echo "Unable to list the artifacts of the run, retrying"
      elif ((count > 0)); then
        echo "Artifact $NAME of job $JOB uploaded"
        exit 0
      elif [[ "$job_status" == completed ]]; then
        echo "Job $JOB ended without uploading the artifact $NAME, its upload step: ${state#* }" >&2
        exit 1
      fi
    else
      echo "Waiting for the artifact $NAME of job $JOB, which is $job_status"
    fi
  fi

  if ((SECONDS >= deadline)); then
    echo "Gave up waiting for the artifact $NAME of job $JOB after ${TIMEOUT}s" >&2
    exit 1
  fi

  sleep "$INTERVAL"
done
