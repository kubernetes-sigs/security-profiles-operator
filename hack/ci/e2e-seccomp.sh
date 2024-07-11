#!/usr/bin/env bash
# Copyright 2022 The Kubernetes Authors.
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

record_seccomp_profiles() {
  echo "Recording seccomp profiles"
  PODNAME=test-pod
  RECORDING=test-recording-$PODNAME

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf $TMP_DIR' EXIT

  echo "Creating profile recording"
  k apply -f examples/profilerecording-seccomp-bpf.yaml

  RUNTIMES=(runc crun)
  for RUNTIME in "${RUNTIMES[@]}"; do
    echo "For runtime $RUNTIME"
    BASEPROFILE=examples/baseprofile-$RUNTIME.yaml

    RC_FILE="$TMP_DIR/rc.yml"
    cat <<EOT >"$RC_FILE"
---
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: $RUNTIME
handler: $RUNTIME
EOT
    echo "Creating runtime class"
    cat "$RC_FILE"

    k apply -f "$RC_FILE"

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
  runtimeClassName: $RUNTIME
  restartPolicy: Never
  containers:
  - name: $PODNAME
    image: alpine:3
    command: ["sleep", "3"]
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

    wait_for seccompprofile $RECORDING

    echo "Patching existing base seccomp profile"
    yq -i ".spec.syscalls = $(
      k get seccompprofile $RECORDING -o json | jq .spec.syscalls -c
    )" "$BASEPROFILE"

    echo "Getting runtime version"
    VERSION=$(crio-"$RUNTIME" --version | grep "$RUNTIME version" | grep -oP '\d+.*')
    yq -i '.metadata.name = "'"$RUNTIME"'-v'"$VERSION"'"' "$BASEPROFILE"

    echo "Deleting seccomp profile"
    k delete seccompprofile $RECORDING
  done

  echo "Diffing output, while ignoring flaky syscalls 'rt_sigreturn', 'sched_yield' and 'tgkill'"
  git diff --exit-code -U0 -I rt_sigreturn -I sched_yield -I tgkill examples

  for RUNTIME in "${RUNTIMES[@]}"; do
    echo "Verifying that the profile for runtime $RUNTIME is available in the GitHub container registry"
    VERSION=$(crio-"$RUNTIME" --version | grep "$RUNTIME version" | grep -oP '\d+.*')
    cosign verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
      "ghcr.io/security-profiles/$RUNTIME:v$VERSION"
  done
}

. "$(dirname "$0")/install-spo.sh"
. "$(dirname "$0")/install-yq.sh"

install_yq
install_operator
record_seccomp_profiles
