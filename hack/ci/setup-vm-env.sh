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

# Waits for the node of the booted Vagrant VM of a CI job and prepares the
# test environment in it, see the e2e-vm action. Flatcar runs the tests in a
# container with the root of the VM at /hostfs and configures git there, see
# hack/ci/e2e-flatcar.sh.
#
# Usage: hack/ci/setup-vm-env.sh VM

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 VM" >&2
  exit 2
fi

VM=$1

case "$VM" in
fedora | debian)
  env_file=env.sh
  artifacts_dir=/vagrant/build/e2e-artifacts
  node_timeout=60s
  ;;
flatcar)
  env_file=env-flatcar.sh
  artifacts_dir=/hostfs/vagrant/build/e2e-artifacts
  node_timeout=600s
  ;;
*)
  echo "Unknown VM $VM" >&2
  exit 1
  ;;
esac
run="./hack/ci/run-$VM.sh"

"$run" kubectl wait --for=condition=ready --timeout="$node_timeout" nodes --all
"$run" kubectl get nodes -o wide
if [[ "$VM" != flatcar ]]; then
  "$run" git config --global --add safe.directory /vagrant
fi
"$run" "echo \"export E2E_ARTIFACTS_DIR=$artifacts_dir\" >> /vagrant/hack/ci/$env_file"
