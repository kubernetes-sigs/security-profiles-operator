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

# Pins the selinuxd images to the current digest of their latest tag. They run
# privileged on every node that enables SELinux, so a moved tag must not change
# what runs without a reviewed change here. Updates the kustomize deployment,
# the Helm values and dependencies.yaml, run `make deployments bundle`
# afterwards to regenerate the manifests. With --check it only reports moved
# tags and fails when there are any, which the weekly dependencies workflow
# does.

set -euo pipefail

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO=quay.io/security-profiles-operator
IMAGES=(selinuxd selinuxd-el8 selinuxd-el9 selinuxd-fedora)
DEPLOYMENT=deploy/kustomize-deployment/manager_deployment.yaml
VALUES=deploy/helm/values.yaml
DEPENDENCIES=dependencies.yaml

CHECK=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK=true
fi

cd "$(git rev-parse --show-toplevel)"

moved=0
for image in "${IMAGES[@]}"; do
  current=$(sed -n "s;^ *value: $REPO/$image@\(sha256:[a-f0-9]\{64\}\)$;\1;p" "$DEPLOYMENT")
  if [[ -z "$current" ]]; then
    echo "No pinned digest of $REPO/$image in $DEPLOYMENT" >&2
    exit 1
  fi

  latest=$("$(crane_bin)" digest "$REPO/$image:latest")
  if [[ "$latest" == "$current" ]]; then
    echo "$REPO/$image is up to date at $current"
    continue
  fi

  echo "$REPO/$image:latest moved from $current to $latest"
  moved=1
  if [[ "$CHECK" == "true" ]]; then
    continue
  fi

  sed -i "s;$current;$latest;g" "$DEPLOYMENT" "$VALUES" "$DEPENDENCIES"
done

if [[ "$CHECK" == "true" && "$moved" -ne 0 ]]; then
  echo "Run hack/update-selinuxd.sh and make deployments bundle to pin the new digests" >&2
  exit 1
fi
