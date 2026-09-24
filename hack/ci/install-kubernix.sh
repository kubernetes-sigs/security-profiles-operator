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

set -euo pipefail

KUBERNIX_VERSION=v0.4.1
KUBERNIX_ROOT=/var/lib/kubernix
KUBERNIX_NODE=kubernix
KUBERNIX_LOG=${RUNNER_TEMP:-/tmp}/kubernix.log
# The root directory of the kubelet, used by install_operator.
export SPO_KUBELET_DIR=$KUBERNIX_ROOT/kubelet/$KUBERNIX_NODE/run

declare -A KUBERNIX_SHA256=(
  [x86_64]=8c9c587048102f58d08f23114bffddb1f9de2f31343f023928ce5433dd589ae4
  [aarch64]=6355552e690117c3f6e33cd83fcfba0ffb073b191e2e7ed075fa26c0082d6ca0
)

# Runs a command in the Nix environment of the cluster, which provides the
# exact binaries the cluster runs on, like the OCI runtimes. Only the PATH is
# passed on to root, so that nothing gets written into the home of the user.
kubernix_env() {
  sudo env "PATH=$PATH" nix develop "$KUBERNIX_ROOT/nix" \
    --no-update-lock-file --command "$@"
}

install_kubernix() {
  echo "Installing kubernix $KUBERNIX_VERSION"
  local arch bin=/usr/local/bin/kubernix
  arch=$(uname -m)

  sudo curl -sSfL --retry 5 --retry-delay 3 -o "$bin" \
    "https://github.com/saschagrunert/kubernix/releases/download/$KUBERNIX_VERSION/kubernix-$arch"
  echo "${KUBERNIX_SHA256[$arch]}  $bin" | sha256sum -c
  sudo chmod +x "$bin"
}

# Boots a single node cluster with CRI-O, which registers the crun (default)
# and runc runtime handlers. The runtimes are pinned by the overlay.
start_kubernix() {
  echo "Preparing the system for kubernix"
  # The node is named after the hostname, which has to resolve.
  echo "127.0.0.1 $KUBERNIX_NODE" | sudo tee -a /etc/hosts
  sudo hostnamectl set-hostname "$KUBERNIX_NODE"

  # CoreDNS binds port 53 of the host.
  echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
  sudo systemctl stop systemd-resolved || true

  sudo modprobe overlay
  sudo modprobe br_netfilter
  sudo sysctl -w \
    net.bridge.bridge-nf-call-ip6tables=1 \
    net.bridge.bridge-nf-call-iptables=1 \
    net.ipv4.conf.all.route_localnet=1 \
    net.ipv4.ip_forward=1

  echo "Starting kubernix, logging to $KUBERNIX_LOG"
  # The cluster keeps running in the background for the following steps, the
  # runner only stops it at the end of the job. The log is written by the user,
  # so that it can be read without sudo.
  # shellcheck disable=SC2024
  sudo env "PATH=$PATH" kubernix \
    --root "$KUBERNIX_ROOT" \
    --overlay "$(dirname "${BASH_SOURCE[0]}")/kubernix-overlay.nix" \
    --log-level debug \
    --no-shell \
    </dev/null >"$KUBERNIX_LOG" 2>&1 &
  # sudo keeps running as the parent of kubernix. It runs as root, so it gets
  # checked through procfs rather than a signal.
  local pid=$!

  # The pid file gets written once the cluster is up. The first start builds
  # parts of the Nix environment, which takes a while on arm64.
  for ((i = 0; i < 180; i++)); do
    if sudo test -f "$KUBERNIX_ROOT/kubernix.pid"; then
      echo "Cluster is up"
      break
    fi
    if [[ ! -d /proc/$pid ]]; then
      echo "kubernix exited unexpectedly"
      cat "$KUBERNIX_LOG"
      exit 1
    fi
    sleep 5
  done
  if ! sudo test -f "$KUBERNIX_ROOT/kubernix.pid"; then
    echo "Timed out waiting for kubernix"
    cat "$KUBERNIX_LOG"
    exit 1
  fi

  # Use the kubectl matching the cluster version.
  # shellcheck disable=SC2016
  kubernix_env sh -c 'ln -sf "$(command -v kubectl)" /usr/local/bin/kubectl'
  # kubectl writes a lock file next to the kubeconfig, so the directory has to
  # belong to the user as well.
  mkdir -p "$HOME/.kube"
  sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" \
    "$KUBERNIX_ROOT/kubeconfig/admin.kubeconfig" "$HOME/.kube/config"

  kubectl wait --for=condition=ready --timeout=120s nodes --all
  kubectl get nodes -o wide
}

# Loads an image archive into the CRI-O storage of the node, which is where
# the images with pull policy IfNotPresent get picked up from.
load_image() {
  local storage=$KUBERNIX_ROOT/crio/$KUBERNIX_NODE/containers
  echo "Loading $1 into the CRI-O storage"
  # podman evaluates the signature policy when loading an image, and nothing
  # else provides one on the runner.
  if [[ ! -f /etc/containers/policy.json ]]; then
    sudo mkdir -p /etc/containers
    sudo cp "$KUBERNIX_ROOT/policy.json" /etc/containers/policy.json
  fi
  # The storage settings match the CRI-O configuration of kubernix, and the
  # empty storage options drop the ones of a storage.conf on the runner.
  kubernix_env podman \
    --root "$storage/storage" \
    --runroot "$storage/run" \
    --storage-driver overlay \
    --storage-opt "" \
    load -i "$1"
}

print_kubernix_logs() {
  echo "---------------------------------"
  echo "kubernix logs"
  echo "---------------------------------"
  cat "$KUBERNIX_LOG" || true
  for f in "$KUBERNIX_ROOT/crio/$KUBERNIX_NODE/crio.log" \
    "$KUBERNIX_ROOT/kubelet/$KUBERNIX_NODE/kubelet.log"; do
    echo "--- $f"
    sudo tail -n 500 "$f" || true
  done
  echo "--- pods"
  kubectl get pods -A -o wide || true
  kubectl -n security-profiles-operator describe pods || true
  kubectl -n security-profiles-operator get spod spod -o yaml || true
  kubectl -n security-profiles-operator logs --all-containers --prefix \
    --tail=-1 --selector 'name in (security-profiles-operator, spod)' || true
  echo "--- events"
  kubectl get events -A --sort-by=.lastTimestamp || true
  echo "---------------------------------"
}
