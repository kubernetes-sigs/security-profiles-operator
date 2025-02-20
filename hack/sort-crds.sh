#!/usr/bin/env bash
# Copyright 2021 The Kubernetes Authors.
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

# Ensure CRDs are generated in sorted manner

TEMP=$(mktemp -d /tmp/spo.make.XXXXX)
delete_temp_dir() {
  if [ -d "${TEMP}" ]; then
    rm -rf "${TEMP}"
  fi
}
trap delete_temp_dir EXIT

cat <<EOF >"${TEMP}/kustomization.yaml"
resources:
EOF

# save output from controller-gen command
echo "$1" | bash >"${TEMP}/tmp_output.yaml"

mkdir -p "${TEMP}/crds"
./build/kubernetes-split-yaml --outdir "${TEMP}/crds" "${TEMP}/tmp_output.yaml"

find "${TEMP}/crds" -type f -exec basename {} \; | sort | xargs -I {} echo "- ./crds/{}" >>"${TEMP}/kustomization.yaml"
cat "${TEMP}/kustomization.yaml"

./build/kustomize build "${TEMP}" -o "$2"
