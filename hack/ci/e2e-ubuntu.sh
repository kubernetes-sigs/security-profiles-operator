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

export E2E_CLUSTER_TYPE=vanilla
export E2E_TEST_LOG_ENRICHER=true
export E2E_TEST_JSON_ENRICHER=true
# The seccomp tests stay with the Prow kind job: they expect the kubelet
# directory at /var/lib/kubelet on the node, while kubernix keeps it below its
# own root (SPO_KUBELET_DIR).
export E2E_TEST_SECCOMP=false
# The BPF recorder records single pods on kubernix, which the
# e2e-seccomp-profile job does for the base profiles and e2e-debian for the
# AppArmor recording. The suite's BPF recorder tests do not work here: the
# multi container deployments of the profile merging tests never get recorded
# (amd64) or crash loop while recorded (arm64). The test case of the BPF log
# enricher source has its own switch, E2E_TEST_BPF_LOG_ENRICHER.
export E2E_TEST_BPF_RECORDER=false
# The curl pods of the profiling test cannot connect to the profiling port of
# the spod pods on kubernix, while the test passes on Fedora and Flatcar.
export E2E_TEST_SKIP='//SPOD:_Profiling_server_protocol'
export E2E_TEST_FLAKY_TESTS_ONLY=${E2E_TEST_FLAKY_TESTS_ONLY:-false}

# The suite deploys copies of the tracked manifests below build/e2e-manifests
# and makes its changes there, so the kubelet directory of the node gets set in
# the tracked manifests, which the copies start from.
if [[ -n "${SPO_KUBELET_DIR:-}" ]]; then
  sed -i "s;value: /var/lib/kubelet$;value: $SPO_KUBELET_DIR;" \
    deploy/operator.yaml deploy/namespace-operator.yaml
fi

if "${E2E_TEST_FLAKY_TESTS_ONLY}"; then
  make test-flaky-e2e
else
  make test-e2e
fi
