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
#
# With E2E_SKIP_ON_SLOW_RUNNER=true a slow runner only gets a warning, and the
# script notes the skip in GITHUB_STEP_SUMMARY, writes slow-runner=true to
# GITHUB_OUTPUT and leaves the test environment unprepared, so that the job
# can skip the tests instead of failing, see the e2e-flakes workflow.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 VM" >&2
  exit 2
fi

# Without GITHUB_OUTPUT the caller could not tell a skip apart from success.
if [[ "${E2E_SKIP_ON_SLOW_RUNNER:-false}" == true && (-z "${GITHUB_OUTPUT:-}" || -z "${GITHUB_STEP_SUMMARY:-}") ]]; then
  echo "E2E_SKIP_ON_SLOW_RUNNER needs GITHUB_OUTPUT and GITHUB_STEP_SUMMARY, run it in GitHub Actions" >&2
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

# On a slow CI runner the cluster in the VM starves: its probes and lease
# renewals time out, every test case runs into its timeouts and the suite
# fails after an hour. kubeadm init with the images pulled before, see
# hack/ci/install-kubernetes.sh, tells such a runner apart: it takes up to 35
# seconds on the Fedora and Debian VMs of a usual runner, and 100 to 210
# seconds on a slow one. Rerunning the job gets another runner. The check comes
# before the node wait, which can time out on such a runner as well.
if [[ "$VM" != flatcar ]]; then
  max_kubeadm_init_seconds=60
  kubeadm_init_seconds=$("$run" cat /var/lib/kubeadm-init-seconds | tr -d '[:space:]') || true
  if [[ ! "$kubeadm_init_seconds" =~ ^[0-9]+$ ]]; then
    echo "::error::No duration of kubeadm init in the VM: $kubeadm_init_seconds"
    exit 1
  fi
  echo "kubeadm init took ${kubeadm_init_seconds}s"
  if ((kubeadm_init_seconds > max_kubeadm_init_seconds)); then
    if [[ "${E2E_SKIP_ON_SLOW_RUNNER:-false}" == true ]]; then
      message="kubeadm init took ${kubeadm_init_seconds}s, more than ${max_kubeadm_init_seconds}s: the runner is too slow for the e2e tests, skipping them"
      echo "::warning::$message"
      echo "slow-runner=true" >>"$GITHUB_OUTPUT"
      # The job stays green, so the summary keeps the skip visible on the run.
      echo "$VM VM: $message" >>"$GITHUB_STEP_SUMMARY"
      exit 0
    fi
    echo "::error::kubeadm init took ${kubeadm_init_seconds}s, more than ${max_kubeadm_init_seconds}s: the runner is too slow for the e2e tests, rerun the job"
    exit 1
  fi
fi

"$run" kubectl wait --for=condition=ready --timeout="$node_timeout" nodes --all
"$run" kubectl get nodes -o wide

if [[ "$VM" != flatcar ]]; then
  "$run" git config --global --add safe.directory /vagrant
fi
"$run" "echo \"export E2E_ARTIFACTS_DIR=$artifacts_dir\" >> /vagrant/hack/ci/$env_file"
