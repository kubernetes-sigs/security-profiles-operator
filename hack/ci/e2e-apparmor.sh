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
  local name="$(grep -o '\btest-recording_test-pod[^ ]*\b' $APPARMOR_PROFILE_FILE)"
  sed -i -e "s/\btest-recording_test-pod[^ ]*\b/test-sleep/g" $APPARMOR_PROFILE_FILE

  diff $APPARMOR_REFERENCE_PROFILE_FILE $APPARMOR_PROFILE_FILE
  echo "${name}"
}

create_pod() {
  local pod_name="$1"
  local pod_file="$2"
  local apparmor_profile="${3-}"
  cat <<EOT >"$pod_file"
---
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  labels:
    app: alpine
spec:
  restartPolicy: Never
  containers:
  - name: $pod_name
    image: alpine:3
    command: ["sleep", "30"]
EOT

  if [[ -n "$apparmor_profile" ]]; then
    cat <<EOT >>"$pod_file"
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: $apparmor_profile
EOT
  fi
  cat "$pod_file"
  k apply -f "$pod_file"
}

wait_for_pod_status() {
  local pod_name="$1"
  local status="$2"
  echo "Waiting for pod status: $status"
  for ((i = 0; i < 10; i++)); do
    if k get pods $pod_name | grep -q $status; then
      echo "Pod reached status: $status "
      break
    fi
    echo "Still waiting ($i)"
    sleep 5
  done
}

check_profile_enforcement() {
  local comamnd="$1"
  local apparmor_profile="$2"
  local pid="$(pidof $comamnd)"
  local enforce="$(cat /proc/${pid}/attr/current)"
  local reference="$apparmor_profile (enforce)"
  if [[ "$reference" != "$enforce" ]]; then
    echo "Apparmor profile $apparmor_profile not enforced: $enforce"
    exit 1
  fi
  echo "Apparmor profile successfully enforced: $enforce"
}

record_apparmor_profile() {
  echo "Enable Apparmor profile"
  k patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
  k rollout status ds spod --timeout 360s
  k_wait spod spod

  echo "Recording apparmor profile"
  echo "--------------------------"

  echo "Creating profile recording $RECORDING_NAME"
  k apply -f $APPARMOR_RECORDING_FILE

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf $TMP_DIR' EXIT

  echo "Creating pod $PODNAME and start recording its apparmor profile"
  pod_file="${TMP_DIR}/${PODNAME}.yml"
  create_pod $PODNAME $pod_file
  wait_for_pod_status "$PODNAME" "Completed"
  echo "Deleting pod $PODNAME"
  k delete -f "$pod_file"

  echo "Deleting profile recoridng $RECORDING_NAME"
  k delete -f "$APPARMOR_RECORDING_FILE"

  wait_for apparmorprofile $APPARMOR_PROFILE_NAME

  echo "Verifing apparmor profile"
  echo "-------------------------"

  echo "Checking the recorded appamror profile matches the reference"
  apparmor_profile=$(check_apparmor_profile)

  echo "Creating pod $PODNAME with recorded profile in security context"
  sec_pod_file="${TMP_DIR}/${PODNAME}-apparmor.yml"
  create_pod $PODNAME $sec_pod_file $apparmor_profile
  wait_for_pod_status "$PODNAME" "Running"

  echo "Checking apparmor profile enforcement on container"
  check_profile_enforcement "sleep" $apparmor_profile

  echo "Deleting pod $PODNAME"
  k delete -f "$sec_pod_file"

  echo "Deleting apparmor profile $APPARMOR_PROFILE_NAME"
  k delete apparmorprofile $APPARMOR_PROFILE_NAME
}

. "$(dirname "$0")/install-spo.sh"
. "$(dirname "$0")/install-yq.sh"

install_yq
install_operator
record_apparmor_profile
