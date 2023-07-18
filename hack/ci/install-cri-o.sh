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

TAG=v1.27.1

curl_retry() {
    curl -sSfL --retry 5 --retry-delay 3 "$@"
}

# We need cosign as well as the bom tool here because the CRI-O installation
# script will automatically verify the signatures based on their existence in
# $PATH.
COSIGN_VERSION=v2.0.2
curl_retry -o /usr/bin/cosign \
    https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/cosign-linux-amd64
chmod +x /usr/bin/cosign
cosign version

BOM_VERSION=v0.5.1
curl_retry -o /usr/bin/bom \
    https://github.com/kubernetes-sigs/bom/releases/download/$BOM_VERSION/bom-amd64-linux
chmod +x /usr/bin/bom
bom version

curl_retry "https://raw.githubusercontent.com/cri-o/cri-o/$TAG/scripts/get" |
    bash -s -- -t "$TAG"

. /etc/os-release

if [[ $ID == fedora ]]; then
    mkdir -p /var/lib/kubelet
    chcon -R -u system_u -r object_r -t var_lib_t /var/lib/kubelet
    printf '[crio.runtime]\nselinux = true' >/etc/crio/crio.conf.d/30-selinux.conf
fi

if [[ $ID == ubuntu ]]; then
    printf '[crio.runtime.runtimes.runc]\n' >/etc/crio/crio.conf.d/10-runc.conf
fi

systemctl enable --now crio.service
