#!/usr/bin/env bash
# Copyright 2024 The Kubernetes Authors.
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
  YQ_VERSION=4.35.2
  curl_retry -o /usr/bin/yq \
    https://github.com/mikefarah/yq/releases/download/v$YQ_VERSION/yq_linux_amd64
  sudo chmod +x /usr/bin/yq
  yq --version
}
