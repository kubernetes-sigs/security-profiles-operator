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

local_ip() {
    ip route get 1.2.3.4 | cut -d ' ' -f7 | tr -d '[:space:]'
}

GOPATH=$(go env GOPATH)

export KUBE_CONTAINER_RUNTIME=remote
export KUBERUN=/var/run/kubernetes
export KUBECONFIG=$KUBERUN/admin.kubeconfig
export PATH="$GOPATH/src/k8s.io/kubernetes/_output/bin:$PATH"

IP=$(local_ip)
export KUBE_MASTER_URL=$IP
export KUBE_MASTER_IP=$IP
export KUBE_MASTER=$IP

alias k=kubectl
