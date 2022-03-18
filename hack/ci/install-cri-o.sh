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

COMMIT_ID=9222794e513040ccb6adeea0703e7a57424606db
TAG=v1.23.2

curl "https://raw.githubusercontent.com/cri-o/cri-o/$COMMIT_ID/scripts/get" | bash -s -- -t "$TAG"

. /etc/os-release

if [[ $ID == fedora ]]; then
    mkdir -p /var/lib/kubelet
    chcon -R -u system_u -r object_r -t var_lib_t /var/lib/kubelet
    printf '[crio.runtime]\nselinux = true' >/etc/crio/crio.conf.d/30-selinux.conf
fi

systemctl enable --now crio.service
