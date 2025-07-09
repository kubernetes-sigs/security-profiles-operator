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
APPARMOR_REFERENCE_PROFILE_FILE="examples/apparmorprofile-sleep"
APPARMOR_REFERENCE_TMP_PROFILE_FILE="/tmp/apparmorprofile-sleep-reference.yaml"
APPARMOR_PROFILE_FILE_COMPLAIN_MODE="examples/apparmorprofile-sleep-complain-mode.yaml"
SLEEP_INTERVAL_RECORDING="30"     # 30s sleep interval during recording.
SLEEP_INTERVAL_VERIFICATION="300" # 5min to make sure that the enforcement check finds a running  PID.
RUNTIMES=(runc crun)
# Default location for CRI-O specific runtime binaries
export PATH="/usr/libexec/crio:$PATH"

create_pod() {
  local pod_name="$1"
  local pod_file="$2"
  local sleep_interval="$3"
  local runtime="$4"
  local apparmor_profile="${5-}"
  cat <<EOT >"$pod_file"
---
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  labels:
    app: alpine
spec:
  runtimeClassName: $runtime
  restartPolicy: Never
  containers:
  - name: $pod_name
    image: alpine:3
    command: ["sleep", "$sleep_interval"]
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
      return 0
    fi
    echo "Still waiting ($i)"
    sleep 5
  done
  return 1
}

check_profile_mode() {
  local command="$1"
  local apparmor_profile="$2"
  local apparmor_profile_mode="$3"
  local pid="$(pidof $command)"
  local mode="$(cat /proc/${pid}/attr/current)"
  local reference="$apparmor_profile ($apparmor_profile_mode)"
  if [[ "$reference" != "$mode" ]]; then
    echo "Apparmor profile $apparmor_profile not in $apparmor_profile_mode mode: $mode"
    exit 1
  fi
  echo "Apparmor profile mode: $mode"
}

# Records and checks if the profile is properly installed by default in enforce mode.
check_apparmor_profile_recording() {
  echo "--------------------------------------------------------------------"
  echo "Checking apparmor profile recording and installation in enforce mode"
  echo "--------------------------------------------------------------------"

  echo "Enable Apparmor profile"
  k patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
  k rollout status ds spod --timeout 360s
  k_wait spod spod

  ensure_runtime_classes

  for runtime in "${RUNTIMES[@]}"; do
    echo "--------------------------"
    echo "Recording apparmor profile"
    echo "--------------------------"

    echo "Creating profile recording $RECORDING_NAME"
    k apply -f $APPARMOR_RECORDING_FILE

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf $TMP_DIR' EXIT

    echo "Creating pod $PODNAME and start recording its apparmor profile"
    pod_file="${TMP_DIR}/${PODNAME}.yml"
    create_pod $PODNAME $pod_file $SLEEP_INTERVAL_RECORDING $runtime
    wait_for_pod_status "$PODNAME" "Completed"
    echo "Deleting pod $PODNAME"
    k delete -f "$pod_file"

    echo "Deleting profile recording $RECORDING_NAME"
    k delete -f "$APPARMOR_RECORDING_FILE"

    wait_for apparmorprofile $APPARMOR_PROFILE_NAME

    k get apparmorprofile -o yaml "$APPARMOR_PROFILE_NAME" \
      >"$APPARMOR_REFERENCE_PROFILE_FILE-$runtime.yaml"

    yq -i '
      del(.metadata.creationTimestamp,
          .metadata.finalizers,
          .metadata.generation,
          .metadata.resourceVersion,
          .metadata.uid)
      ' "$APPARMOR_REFERENCE_PROFILE_FILE-$runtime.yaml"

    echo "------------------------------------"
    echo "$APPARMOR_REFERENCE_PROFILE_FILE-$runtime.yaml"
    echo "------------------------------------"
    cat "$APPARMOR_REFERENCE_PROFILE_FILE-$runtime.yaml"
    echo "------------------------------------"

    echo "Creating pod $PODNAME with recorded profile in security context"
    sec_pod_file="${TMP_DIR}/${PODNAME}-apparmor.yml"
    create_pod $PODNAME $sec_pod_file $SLEEP_INTERVAL_VERIFICATION $runtime $APPARMOR_PROFILE_NAME
    wait_for_pod_status "$PODNAME" "Running" || k describe pod test-pod

    echo "Checking apparmor profile enforcement on container"
    check_profile_mode "sleep" $APPARMOR_PROFILE_NAME "enforce"

    echo "Deleting pod $PODNAME"
    k delete -f "$sec_pod_file"

    echo "Deleting apparmor profile $APPARMOR_PROFILE_NAME"
    k delete apparmorprofile $APPARMOR_PROFILE_NAME

  done

  print_spo_logs
  git diff --exit-code examples
}

# Install a profile in complain mode, and checks if the pod properly starts
# even though all access is denied.
check_apparmor_complain_mode() {
  echo "-------------------------------------------------------"
  echo "Checking apparmor profile installation in complain mode"
  echo "-------------------------------------------------------"

  echo "Enable Apparmor profile"
  k patch spod spod --type=merge -p '{"spec":{"enableAppArmor":true}}'
  k rollout status ds spod --timeout 360s
  k_wait spod spod

  echo "---------------------------"
  echo "Installing apparmor profile"
  echo "---------------------------"

  echo "Install apparmor profile in complain mode $APPARMOR_PROFILE_FILE_COMPLAIN_MODE"
  k apply -f $APPARMOR_PROFILE_FILE_COMPLAIN_MODE
  wait_for apparmorprofile $APPARMOR_PROFILE_NAME

  echo "--------------------------"
  echo "Verifying apparmor profile"
  echo "--------------------------"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf $TMP_DIR' EXIT

  echo "Creating pod $PODNAME with apparmor profile in complain mode in security context"
  runtime="crun"
  sec_pod_file="${TMP_DIR}/${PODNAME}-apparmor.yml"
  create_pod $PODNAME $sec_pod_file $SLEEP_INTERVAL_VERIFICATION $runtime $APPARMOR_PROFILE_NAME
  wait_for_pod_status "$PODNAME" "Running"

  echo "Checking apparmor profile is in complain mode on container"
  check_profile_mode "sleep" $APPARMOR_PROFILE_NAME "complain"

  echo "Deleting pod $PODNAME"
  k delete -f "$sec_pod_file"

  echo "Deleting apparmor profile $APPARMOR_PROFILE_NAME"
  k delete apparmorprofile $APPARMOR_PROFILE_NAME
}

. "$(dirname "$0")/install-spo.sh"
. "$(dirname "$0")/install-yq.sh"

install_yq
install_operator

check_apparmor_profile_recording
check_apparmor_complain_mode
