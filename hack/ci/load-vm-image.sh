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

# Copies the archive of the operator image into the running Vagrant VM of a CI
# job and loads it into the image storage of the container runtime of the
# node. The VM boots without the image when VAGRANT_BUILD_IMAGE=false, so that
# it can boot while the image job of the workflow still builds it, see the
# e2e-vm action.
#
# Usage: hack/ci/load-vm-image.sh VM ARCHIVE

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 VM ARCHIVE" >&2
  exit 2
fi

VM=$1
ARCHIVE=$2

# Outside of the synced repository, which the shared folder of the Debian VM
# would write back to the host.
REMOTE_ARCHIVE=/tmp/image.tar

case "$VM" in
fedora | debian)
  # CRI-O shares the image storage of podman.
  LOAD="podman load -i $REMOTE_ARCHIVE"
  ;;
flatcar)
  LOAD="ctr -n=k8s.io image import $REMOTE_ARCHIVE"
  ;;
*)
  echo "Unknown VM $VM" >&2
  exit 1
  ;;
esac

SSH_CONFIG=$(mktemp)
trap 'rm -f "$SSH_CONFIG"' EXIT

vagrant ssh-config >"$SSH_CONFIG"

echo "Copying $ARCHIVE into the VM"
scp -F "$SSH_CONFIG" "$ARCHIVE" "default:$REMOTE_ARCHIVE"

echo "Loading the image"
ssh -F "$SSH_CONFIG" default "sudo sh -c '$LOAD && rm -f $REMOTE_ARCHIVE'"
