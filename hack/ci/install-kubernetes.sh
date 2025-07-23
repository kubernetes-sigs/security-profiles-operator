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

set -euox pipefail

# Setup cluster
IP=$(ip route get 1.2.3.4 | cut -d ' ' -f7 | tr -d '[:space:]')
swapoff -a
modprobe br_netfilter
sysctl -w net.ipv4.ip_forward=1
echo "Number of CPUs: $(nproc)"
kubeadm init --apiserver-cert-extra-sans="$IP"

# Setup kubectl
USER=vagrant
mkdir /home/$USER/.kube
cp /etc/kubernetes/admin.conf /home/$USER/.kube/config
chown -R $USER:$USER /home/$USER/.kube

mkdir /root/.kube
cp /etc/kubernetes/admin.conf /root/.kube/config

# Configure cluster
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl wait -n kube-system --timeout=180s --for=condition=available deploy coredns
kubectl wait --timeout=180s --for=condition=ready pods --all -A
kubectl get pods -A
