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

# Starts a kubernix cluster with the operator image given as first argument for
# the Go e2e suite, which runs on the node itself. The cluster keeps running for
# the following steps, which get the kubelet directory as SPO_KUBELET_DIR.

. "$(dirname "$0")/install-kubernix.sh"

# The log enricher reads the audit messages of the kernel from syslog, and must
# not miss any of them.
if [[ ! -f /var/log/syslog ]]; then
  sudo apt-get update
  sudo apt-get install -y rsyslog
fi
sudo sysctl -w kernel.printk_ratelimit=0 kernel.printk_ratelimit_burst=0

install_kubernix
start_kubernix
load_image "${1:-image.tar}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "SPO_KUBELET_DIR=$SPO_KUBELET_DIR" >>"$GITHUB_ENV"
fi
