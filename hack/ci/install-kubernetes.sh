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

ENVFILE=$(dirname "${BASH_SOURCE[0]}")/env-fedora.sh
. "$ENVFILE"

K8SPATH="$GOPATH/src/k8s.io"
VERSION=v1.27.0

download-kubernetes() {
    export KUBERNETES_RELEASE=$VERSION
    export KUBERNETES_SKIP_CONFIRM=1
    export KUBERNETES_SKIP_CREATE_CLUSTER=1
    cluster/get-kube.sh

    mkdir -p _output/bin
    tar xfz kubernetes/server/kubernetes-server-linux-amd64.tar.gz
    cp kubernetes/server/bin/{kubectl,kube-apiserver,kube-controller-manager,kube-proxy,kube-scheduler,kubelet} \
        _output/bin
}

local-up() {
    export PATH="$GOPATH/src/k8s.io/kubernetes/third_party/etcd:$PATH"
    export CONTAINER_RUNTIME=remote
    export CGROUP_DRIVER=systemd
    export CONTAINER_RUNTIME_ENDPOINT=/var/run/crio/crio.sock
    export CGROUPS_PER_QOS=false
    export ALLOW_PRIVILEGED=1
    export KUBELET_FLAGS='--enforce-node-allocatable='

    echo "Using IP: $IP"
    export DNS_SERVER_IP=$IP
    export API_HOST_IP=$IP

    iptables -F
    download-kubernetes
    hack/local-up-cluster.sh -O
}

mkdir -p "$K8SPATH"
cd "$K8SPATH"

TARBALL=k8s.tar.gz
curl -sfL --retry 5 --retry-delay 3 --show-error \
    -o $TARBALL https://github.com/kubernetes/kubernetes/tarball/$VERSION
tar xfz $TARBALL
rm $TARBALL
mv kubernetes-kubernetes-* kubernetes
cd kubernetes

hack/install-etcd.sh

OUTPUT=$(mktemp)
local-up 2>&1 | tee "$OUTPUT" &
PID=$!

echo Waiting for hack/local-up-cluster.sh
until grep -q "Local Kubernetes cluster is running" "$OUTPUT"; do
    if ! ps $PID >/dev/null; then
        exit 1
    fi
    sleep 1
done

echo Cluster is up and running
