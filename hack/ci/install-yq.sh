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

install_yq() {
  echo "Installing yq"
  local arch sha256 download
  YQ_VERSION=4.53.6
  # Bump together with YQ_VERSION, see dependencies.yaml.
  YQ_SHA256_amd64=c5f056448f973ae7d39b5401949648a78f2dc1947d6a8eb65be60d5c504b9385
  YQ_SHA256_arm64=88a1016bc1d657375a35864e4f44b6f333df8ff97b559f51bba0adcb2169df09
  case "$(uname -m)" in
  x86_64) arch=amd64 sha256=$YQ_SHA256_amd64 ;;
  aarch64) arch=arm64 sha256=$YQ_SHA256_arm64 ;;
  *)
    echo "Unsupported architecture $(uname -m)" >&2
    return 1
    ;;
  esac
  download=$(mktemp)
  curl -sSfL --retry 5 --retry-delay 3 -o "$download" \
    "https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/yq_linux_$arch"
  echo "$sha256  $download" | sha256sum -c -
  sudo install -m 0755 "$download" /usr/bin/yq
  rm -f "$download"
  yq --version
}
