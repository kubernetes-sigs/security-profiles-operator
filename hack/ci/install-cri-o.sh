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

TAG=v1.25.1

export PATH=$PATH:/usr/local/go/bin
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"

# We need cosign as well as the bom tool here because the CRI-O installation
# script will automatically verify the signatures based on their existence in
# $PATH.
COSIGN_VERSION=v1.13.1
go install github.com/sigstore/cosign/cmd/cosign@$COSIGN_VERSION
cp "$GOBIN/cosign" /usr/bin
cosign version

BOM_VERSION=v0.4.1
go install sigs.k8s.io/bom/cmd/bom@$BOM_VERSION
cp "$GOBIN/bom" /usr/bin
bom version

curl -sSfL --retry 5 --retry-delay 3 "https://raw.githubusercontent.com/cri-o/cri-o/$TAG/scripts/get" |
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
