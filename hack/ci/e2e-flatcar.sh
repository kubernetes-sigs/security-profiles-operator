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

export E2E_CLUSTER_TYPE="vanilla"
export E2E_SPOD_CONFIG="test/flatcar-spod-config.yaml"
export E2E_TEST_SECCOMP=false
export E2E_TEST_SELINUX=false
export E2E_TEST_LOG_ENRICHER=false
export E2E_TEST_BPF_RECORDER=false
# The curl pods of the metrics HTTP version test get no output on Flatcar.
export E2E_TEST_METRICS_HTTP=false
export E2E_TEST_FLAKY_TESTS_ONLY=${E2E_TEST_FLAKY_TESTS_ONLY:-false}

export HOSTFS_DEV_MOUNT_PATH="/hostfs"
export NODE_ROOTFS_PREFIX=$HOSTFS_DEV_MOUNT_PATH

# Setup the Go environment variables
export PATH="$HOSTFS_DEV_MOUNT_PATH/opt/go/bin:$PATH"
export GOPATH="$HOSTFS_DEV_MOUNT_PATH/opt/go"
export GOBIN="$GOPATH/bin"

# Add the binaries to the path
export PATH="$HOSTFS_DEV_MOUNT_PATH/opt/bin:$PATH"

export KUBECONFIG=$HOSTFS_DEV_MOUNT_PATH/etc/kubernetes/admin.conf

# Configure git to consider the mounted host filesystem as safe
git config --global --add safe.directory "/hostfs/vagrant"

# CI compiles the tests outside of the VM, see E2E_TEST_BINARY in the Makefile.
# The artifact download loses the executable bit. The VM syncs build/ of the
# checkout, so a local run uses a test binary which is left there, remove it
# to test the sources instead.
if [[ -f build/e2e.test ]]; then
    chmod +x build/e2e.test
    export E2E_TEST_BINARY=build/e2e.test
    echo "Using the prebuilt e2e test binary $E2E_TEST_BINARY of $(date -r "$E2E_TEST_BINARY")"
else
    echo "No prebuilt e2e test binary, compiling the tests"
    # The compilation needs the space of the developer container, so it
    # starts without and leaves no build cache behind.
    go clean -cache -testcache || true
    cleanup() {
        go clean -cache -testcache || true
    }
    trap cleanup EXIT
fi

case "${E2E_TEST_FLAKY_TESTS_ONLY}" in
true) make test-flaky-e2e ;;
false) make test-e2e ;;
*)
    echo "E2E_TEST_FLAKY_TESTS_ONLY must be true or false, not ${E2E_TEST_FLAKY_TESTS_ONLY}" >&2
    exit 1
    ;;
esac
