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

PODNAME=test-pod
RECORDING_NAME="test-recording"
APPARMOR_RECORDING_FILE="examples/profilerecording-apparmor-bpf.yaml"
APPARMOR_PROFILE_NAME="test-recording-$PODNAME"
APPARMOR_PROFILE_FILE="/tmp/apparmorprofile-sleep.yaml"
APPARMOR_REFERENCE_PROFILE_FILE="examples/apparmorprofile-sleep.yaml"

# Retrieves the recorded apaprmor profile from the cluster and
# cleans up the variances.
check_apparmor_profile() {
  k get apparmorprofile -o yaml "$APPARMOR_PROFILE_NAME" >"$APPARMOR_PROFILE_FILE"

  # clean up the variance in the recorded apparmor profile
  yq -i ".spec" $APPARMOR_PROFILE_FILE
  sed -i -e "s/\btest-recording_test-pod[^ ]*\b/test-sleep/g" $APPARMOR_PROFILE_FILE
  sed -i -e '/\/var\/lib\/containers\/storage\/overlay/d' $APPARMOR_PROFILE_FILE
  sed -i -e '/\/proc\/@{pid}\/task/d' $APPARMOR_PROFILE_FILE

  diff $APPARMOR_REFERENCE_PROFILE_FILE $APPARMOR_PROFILE_FILE
}

record_apparmor_profile() {
  echo "Enable Apparmor profile"
  k patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
  k rollout status ds spod --timeout 360s
  k_wait spod spod

  echo "Recording apparmor profile"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf $TMP_DIR' EXIT

  echo "Creating profile recording"
  k apply -f $APPARMOR_RECORDING_FILE

  POD_FILE="$TMP_DIR/pod.yml"
  cat <<EOT >"$POD_FILE"
---
apiVersion: v1
kind: Pod
metadata:
  name: $PODNAME
  labels:
    app: alpine
spec:
  restartPolicy: Never
  containers:
  - name: $PODNAME
    image: alpine:3
    command: ["sleep", "20"]
EOT
  echo "Creating pod:"
  cat "$POD_FILE"

  k apply -f "$POD_FILE"

  echo "Waiting for pod to be completed"
  for ((i = 0; i < 10; i++)); do
    if k get pods $PODNAME | grep -q Completed; then
      echo "Pod completed"
      break
    fi
    echo "Still waiting ($i)"
    sleep 5
  done

  echo "Deleting pod"
  k delete -f "$POD_FILE"

  wait_for apparmorprofile $APPARMOR_PROFILE_NAME

  check_apparmor_profile

  echo "Cleaning up profile $APPARMOR_PROFILE_NAME and recording $RECORDING_NAME resources"
  k delete -f "$APPARMOR_RECORDING_FILE"
  k delete apparmorprofile $APPARMOR_PROFILE_NAME
}

. "$(dirname "$0")/install-spo.sh"
. "$(dirname "$0")/install-yq.sh"

install_yq
install_operator
record_apparmor_profile
