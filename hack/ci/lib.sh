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

# shellcheck shell=bash

# Shared helpers of the CI scripts in hack/ci. Source this file, it does not
# change shell options.

# The scripts sourcing this file use some of the variables.
# shellcheck disable=SC2034

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

# The namespace the CI scripts install the operator into.
SPO_NAMESPACE=security-profiles-operator

# The cert-manager release the test clusters install. Bump the checksum of its
# cert-manager.yaml together with the version, see dependencies.yaml.
CERT_MANAGER_VERSION=v1.21.2
CERT_MANAGER_SHA256=e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f

# Runs kubectl in the namespace of the operator.
k() {
  kubectl -n "$SPO_NAMESPACE" "$@"
}

# Installs cert-manager from its release manifest after verifying the checksum
# and waits until its deployments are available. The optional argument is the
# timeout of the wait, five minutes by default.
install_cert_manager() {
  local timeout="${1:-300s}" manifest

  echo "Installing cert-manager $CERT_MANAGER_VERSION"
  manifest=$(mktemp) || return 1
  if ! download_verified \
    "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" \
    "$CERT_MANAGER_SHA256" "$manifest" ||
    ! kubectl apply -f "$manifest"; then
    rm -f "$manifest"
    return 1
  fi
  rm -f "$manifest"

  # The deployments exist right after the apply, their pods may not yet.
  kubectl -n cert-manager wait --timeout "$timeout" --for condition=available deployment --all
}

# Runs the command until it succeeds, at most tries times with delay seconds in
# between. It returns 1 if the command never succeeded.
wait_until() {
  local tries="$1" delay="$2" i
  shift 2

  for ((i = 0; i < tries; i++)); do
    if "$@"; then
      return 0
    fi
    echo "Still waiting ($i)"
    sleep "$delay"
  done

  return 1
}
