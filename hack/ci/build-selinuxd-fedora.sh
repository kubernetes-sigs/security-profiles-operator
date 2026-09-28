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

# Builds the selinuxd image for the Fedora release of the e2e VM.
#
# The published selinuxd-fedora image is based on Fedora 35, whose semodule
# cannot build the policy of the VM ("Re-declaration of role system_r"), and
# which tries to install the temporary files of the written policies. selinuxd
# is therefore built on the Fedora release of the VM, which is taken from
# hack/ci/Vagrantfile-fedora. CI builds it outside of the VM in parallel to the
# operator image, because building it inside the VM takes about 10 minutes.

set -euo pipefail

SELINUXD_COMMIT=6bd301111e8f151e1bf5931cb46a6e50c34b42c8
IMAGE=${1:-localhost/selinuxd-fedora:latest}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
FEDORA_VERSION=$(sed -n 's|.*config.vm.box = "fedora/\([0-9]*\)-.*|\1|p' \
  "$ROOT/hack/ci/Vagrantfile-fedora")
if [[ -z $FEDORA_VERSION ]]; then
  echo "Unable to find the Fedora release in hack/ci/Vagrantfile-fedora" >&2
  exit 1
fi

SELINUXD_DIR=$(mktemp -d)
trap 'rm -rf "$SELINUXD_DIR"' EXIT

git -C "$SELINUXD_DIR" init -q
git -C "$SELINUXD_DIR" fetch -q --depth 1 \
  https://github.com/containers/selinuxd "$SELINUXD_COMMIT"
git -C "$SELINUXD_DIR" checkout -q FETCH_HEAD

sed -i "s|fedora-minimal:[0-9]*|fedora-minimal:$FEDORA_VERSION|" \
  "$SELINUXD_DIR/images/fedora/Dockerfile"

podman build -f "$SELINUXD_DIR/images/fedora/Dockerfile" \
  -t "$IMAGE" "$SELINUXD_DIR"
