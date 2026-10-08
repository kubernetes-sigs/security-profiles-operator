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

# Sets the version of the module of this repository in the given SPDX 3 SBOMs,
# see set_sbom_module_version in hack/lib/common.sh.
#
# Usage: hack/set-sbom-module-version.sh SBOM...

set -euo pipefail

# The jq of the host, like hack/native-sbom.sh, since the one jq_bin downloads
# only runs on linux/amd64 and the spoc-sbom target runs on any build host.
JQ="${JQ:-jq}"

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

for sbom in "$@"; do
  set_sbom_module_version "$sbom"
done
