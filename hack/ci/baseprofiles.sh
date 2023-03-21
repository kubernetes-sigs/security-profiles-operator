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

install_yq() {
    echo "Installing yq"
    go install -mod=mod github.com/mikefarah/yq/v4@latest
    GOPATH=$(go env GOPATH)
    export PATH=$GOPATH/bin:$PATH
    yq --version
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
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
    kubectl -n cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

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

record_baseprofile() {
    echo "Recording baseprofiles"
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
        VERSION=$($RUNTIME --version | grep "$RUNTIME version" | grep -oP '\d+.*')
        yq -i '.metadata.name = "'"$RUNTIME"'-v'"$VERSION"'"' "$BASEPROFILE"

        echo "Deleting seccomp profile"
        k delete seccompprofile $RECORDING
    done

    echo "Diffing output, while ignoring flaky syscalls 'rt_sigreturn', 'sched_yield' and 'tgkill'"
    git diff --exit-code -U0 -I rt_sigreturn -I sched_yield -I tgkill examples

    echo "Verifying that profile is available in the GitHub container registry"
    cosign verify --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' \
        "ghcr.io/security-profiles/$RUNTIME:v$VERSION"
}

install_yq
install_operator
record_baseprofile
