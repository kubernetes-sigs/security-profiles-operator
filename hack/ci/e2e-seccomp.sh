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

set -euo pipefail

# Records the base profiles of the OCI runtimes on the architecture of the
# host and writes them into the directory given as first argument, from which
# update-base-profiles.sh merges the recordings of all architectures.
record_seccomp_profiles() {
  echo "Recording seccomp profiles"
  PODNAME=test-pod
  RECORDING=test-recording-$PODNAME
  OUTPUT_DIR=$1
  mkdir -p "$OUTPUT_DIR"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf $TMP_DIR' EXIT

  ensure_runtime_classes

  echo "Creating profile recording"
  k apply -f examples/profilerecording-seccomp-bpf.yaml

  RUNTIMES=(runc crun)

  for RUNTIME in "${RUNTIMES[@]}"; do
    echo "For runtime $RUNTIME"
    OUTPUT=$OUTPUT_DIR/$RUNTIME.json

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

    # A pod which never completes leaves no recording, so fail here instead
    # of waiting for the profile.
    echo "Waiting for pod to be completed"
    k wait --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s pod/$PODNAME

    # The recorder collects the profile when the pod succeeded. Deleting the
    # pod before that records the syscalls of the runtime tearing down the
    # container, like umount2, into the profile.
    wait_for seccompprofile $RECORDING

    echo "Getting runtime version"
    VERSION=$(kubernix_env "$RUNTIME" --version | grep "$RUNTIME version" | grep -oP '\d+.*')

    echo "Writing recording to $OUTPUT"
    k get seccompprofile $RECORDING -o json |
      jq --arg version "$VERSION" \
        '{version: $version, architectures: .spec.architectures, syscalls: .spec.syscalls}' \
        >"$OUTPUT"
    cat "$OUTPUT"

    # kubectl waits until the pod is gone, so no late recording of it can
    # reach the next runtime.
    echo "Deleting pod"
    k delete -f "$POD_FILE"

    echo "Deleting seccomp profile"
    k delete seccompprofile $RECORDING
  done

  print_spo_logs
}

. "$(dirname "$0")/install-spo.sh"
. "$(dirname "$0")/install-kubernix.sh"

install_kubernix
start_kubernix
load_image image.tar
install_operator
record_seccomp_profiles "${1:-build/recordings}"
