#!/usr/bin/env bash
# Copyright 2021 The Kubernetes Authors.
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
export OPERATOR_MANIFEST="deploy/webhook-operator.yaml" 
export E2E_TEST_SELINUX=true
export E2E_TEST_LOG_ENRICHER=true
export E2E_TEST_LABEL_POD_DENIALS=true
export E2E_TEST_BPF_RECORDER=true
export E2E_TEST_PROFILE_RECORDING=true
export E2E_SKIP_NAMESPACED_TESTS=true
export E2E_TEST_SECCOMP=true
export E2E_TEST_WEBHOOK_CONFIG=false

make test-e2e
