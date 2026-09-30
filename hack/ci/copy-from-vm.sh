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

# Copies a file or directory out of the Vagrant VM of a CI job into a local
# directory. The VM only gets the repository synced in, so the reports and
# diagnostics the tests write there have to be copied out. The tests run as
# root, so the files get made readable for the SSH user first. A path which
# does not exist is not an error, since the tests may have failed before
# writing it, every other failure is.
#
# Usage: hack/ci/copy-from-vm.sh REMOTE_PATH LOCAL_DIR

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 REMOTE_PATH LOCAL_DIR" >&2
  exit 2
fi

REMOTE_PATH=$1
LOCAL_DIR=$2

SSH_CONFIG=$(mktemp)
trap 'rm -f "$SSH_CONFIG"' EXIT

vagrant ssh-config >"$SSH_CONFIG"

REMOTE_PATH_QUOTED=$(printf '%q' "$REMOTE_PATH")

# test exits with 1 if the path does not exist, ssh with 255 if it fails.
RC=0
ssh -F "$SSH_CONFIG" default "sudo test -e $REMOTE_PATH_QUOTED" || RC=$?
if [[ $RC -eq 1 ]]; then
  echo "$REMOTE_PATH does not exist in the VM, nothing to copy"
  exit 0
elif [[ $RC -ne 0 ]]; then
  echo "Unable to check $REMOTE_PATH in the VM, exit code $RC" >&2
  exit "$RC"
fi

ssh -F "$SSH_CONFIG" default "sudo chmod -R a+rX $REMOTE_PATH_QUOTED"

mkdir -p "$LOCAL_DIR"
scp -r -F "$SSH_CONFIG" "default:$REMOTE_PATH" "$LOCAL_DIR/"
