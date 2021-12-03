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

COMMIT_ID="d7cc66fe80c51a197d13a642ad5bddd9dc7e9f74"

curl "https://raw.githubusercontent.com/cri-o/cri-o/${COMMIT_ID}/scripts/get" | bash

chcon -u system_u -r object_r -t container_runtime_exec_t \
    /usr/local/bin/crio \
    /usr/local/bin/crio-status \
    /usr/local/bin/runc \
    /usr/local/bin/crun

chcon -u system_u -r object_r -t bin_t \
    /usr/local/bin/conmon \
    /usr/local/bin/crictl \
    /usr/local/bin/pinns

chcon -R -u system_u -r object_r -t bin_t /opt/cni/bin

mkdir -p /var/lib/kubelet
chcon -R -u system_u -r object_r -t var_lib_t /var/lib/kubelet

mkdir -p /etc/crio/crio.conf.d

cat <<EOT >>/etc/crio/crio.conf.d/30-selinux.conf
[crio.runtime]
selinux = true
EOT

chcon -R -u system_u -r object_r -t container_config_t \
    /etc/crio \
    /etc/crio/crio.conf \
    /usr/local/share/oci-umount/oci-umount.d/crio-umount.conf

systemctl enable crio.service
restorecon /usr/local/lib/systemd/system/crio.service
systemctl start crio.service
