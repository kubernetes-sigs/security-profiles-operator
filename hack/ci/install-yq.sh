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

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

install_yq() {
  echo "Installing yq"
  local arch sha256 download
  YQ_VERSION=4.54.1
  # Bump together with YQ_VERSION, see dependencies.yaml.
  YQ_SHA256_amd64=8e34fc298390875de416e6a4afcb8cabeceb25d9aa8506c1a2f9353cf702ea5f
  YQ_SHA256_arm64=189088da0c6429ec5178dfaab1a114805f6cab0b61b165ab236efedf1d57a71b
  case "$(uname -m)" in
  x86_64) arch=amd64 sha256=$YQ_SHA256_amd64 ;;
  aarch64) arch=arm64 sha256=$YQ_SHA256_arm64 ;;
  *)
    echo "Unsupported architecture $(uname -m)" >&2
    return 1
    ;;
  esac
  download=$(mktemp)
  download_verified \
    "https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/yq_linux_$arch" \
    "$sha256" "$download"
  sudo install -m 0755 "$download" /usr/bin/yq
  rm -f "$download"
  yq --version
}
