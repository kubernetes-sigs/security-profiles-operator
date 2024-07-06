#!/usr/bin/env bash
# Copyright 2024 The Kubernetes Authors.
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

curl_retry() {
  sudo curl -sSfL --retry 5 --retry-delay 3 "$@"
}

k() {
  kubectl -n security-profiles-operator "$@"
}

k_wait() {
  k wait --timeout 120s --for condition=ready "$@"
}

wait_for_pod_name_label() {
  echo "Waiting for pod with label name=$1"

  for ((i = 0; i < 10; i++)); do
    FOUND=$(k get pods -l name="$1" 2>/dev/null)
    if [[ $FOUND ]]; then
      echo "Found pod"
      return
    fi
    echo "Still waiting ($i)"
    sleep 5
  done

  echo "Timed out waiting for pod label name=$1"
  exit 1
}

wait_for() {
  echo "Waiting for $*"
  for ((i = 0; i < 10; i++)); do
    if k get "$@" 2>/dev/null; then
      echo "Found Kubernetes object $*"
      return
    fi
    echo "Still waiting ($i)"
    sleep 5
  done

  echo "Timed out waiting for $*"
  exit 1
}

install_operator() {
  echo "Installing security-profiles-operator"
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.0/cert-manager.yaml
  k_wait -n cert-manager pod -l app.kubernetes.io/instance=cert-manager

  git apply hack/deploy-localhost.patch
  kubectl apply -f deploy/operator.yaml
  kubectl label ns security-profiles-operator spo.x-k8s.io/enable-recording=

  k_wait pod -l name=security-profiles-operator

  wait_for_pod_name_label security-profiles-operator-webhook
  k_wait pod -l name=security-profiles-operator-webhook

  wait_for_pod_name_label spod
  k_wait pod -l name=spod

  wait_for spod spod
  k patch spod spod --type=merge -p '{"spec":{"enableBpfRecorder":true}}'
  k rollout status ds spod --timeout 360s
  k_wait spod spod
}
