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
  print_spo_logs
  exit 1
}

print_spo_logs() {
    echo "---------------------------------"
    echo "Logs"
    echo "---------------------------------"
    k logs --selector name!=nonexistent --all-pods --all-containers --since=10m --prefix --tail=-1
    echo "---------------------------------"
}

ensure_runtime_classes() {
  RUNTIMES=(runc crun)
  for RUNTIME in "${RUNTIMES[@]}"; do
    echo "Installing RuntimeClass $RUNTIME..."
    cat <<EOF | k apply -f -
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $RUNTIME
handler: $RUNTIME
EOF
  done
}

install_operator() {
  echo "Installing security-profiles-operator"
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.2/cert-manager.yaml
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
  INITIAL_SPOD_DS_VERSION=$(k get controllerrevision -l name=spod --sort-by=.revision -o=jsonpath='{.items[-1].revision}' 2>/dev/null)

  if [[ -z "$INITIAL_SPOD_DS_VERSION" ]]; then
      echo "Error: DaemonSet 'spod' not found or could not get its status."
      exit 1
  fi
  k patch spod spod --type=merge -p '{"spec":{"enableBpfRecorder":true}}'
  # Wait for security profiles operator to modify the spod daemonset
  sleep 5
  k rollout status ds spod --timeout 360s
  PATCHED_SPOD_DS_VERSION=$(k get controllerrevision -l name=spod --sort-by=.revision -o=jsonpath='{.items[-1].revision}' 2>/dev/null)

  if [ "$PATCHED_SPOD_DS_VERSION" -gt "$INITIAL_SPOD_DS_VERSION" ]; then
      echo "Success! The DaemonSet version has been updated from $INITIAL_SPOD_DS_VERSION to $PATCHED_SPOD_DS_VERSION."
  else
      echo "Failure. The DaemonSet version did not change. It is still $PATCHED_SPOD_DS_VERSION."
      exit 1
  fi
  k_wait spod spod
}
