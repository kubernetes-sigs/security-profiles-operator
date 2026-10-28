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

# Installs vagrant and VirtualBox on a GitHub Actions runner and unloads the
# KVM modules, which conflict with VirtualBox, see the setup-vagrant action.

set -euo pipefail

# The fingerprints of the HashiCorp and the Oracle VirtualBox Linux package
# signing keys, see https://www.hashicorp.com/en/trust/security and
# https://www.virtualbox.org/wiki/Linux_Downloads. apt trusts the keys for
# their repositories, so they are checked before they get installed. A key
# rotation fails the installation until the fingerprint gets updated.
HASHICORP_FINGERPRINT=D55C0D1AC78A8D8126CB631CFC9CA96ACA026560
ORACLE_VBOX_FINGERPRINT=B9F8D658297AF3EFC18D5CDFA2F683C52980AECF

# add_repository NAME KEY_URL FINGERPRINT REPOSITORY COMPONENT
add_repository() {
  local key="$RUNNER_TEMP/$1.asc" keyring="/usr/share/keyrings/$1-archive-keyring.gpg"
  curl -fsSL --retry 5 --retry-delay 3 -o "$key" "$2"
  # The fingerprints of the primary keys, there must be exactly the one.
  local fingerprints
  fingerprints=$(gpg --show-keys --with-colons "$key" |
    awk -F: '$1 == "pub" { primary = 1; next } $1 == "fpr" && primary { print $10; primary = 0 }')
  if [[ "$fingerprints" != "$3" ]]; then
    echo "Unexpected $1 key fingerprints: $fingerprints" >&2
    exit 1
  fi
  sudo gpg --dearmor -o "$keyring" "$key"
  rm -f "$key"
  echo "deb [signed-by=$keyring] $4 $(lsb_release -cs) $5" | sudo tee "/etc/apt/sources.list.d/$1.list"
}

add_repository hashicorp https://apt.releases.hashicorp.com/gpg \
  "$HASHICORP_FINGERPRINT" https://apt.releases.hashicorp.com main
# The VirtualBox of Ubuntu lags behind the kernels of the runner images, its
# 7.0 kernel modules fail to build for Linux 7.0.
add_repository oracle-virtualbox https://www.virtualbox.org/download/oracle_vbox_2016.asc \
  "$ORACLE_VBOX_FINGERPRINT" https://download.virtualbox.org/virtualbox/debian contrib
sudo apt-get update
sudo apt-get install -y vagrant virtualbox-7.2
# The package only warns if its kernel modules fail to build.
sudo modprobe vboxdrv

sudo modprobe -r kvm_amd kvm_intel kvm || true
