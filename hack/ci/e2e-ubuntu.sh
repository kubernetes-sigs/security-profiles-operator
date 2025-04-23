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
export E2E_TEST_LOG_ENRICHER=true
export E2E_TEST_JSON_ENRICHER=false
export E2E_TEST_SECCOMP=false
export E2E_TEST_FLAKY_TESTS_ONLY=${E2E_TEST_FLAKY_TESTS_ONLY:-false}

if "${E2E_TEST_FLAKY_TESTS_ONLY}"; then
  make test-flaky-e2e
else
  make test-e2e
fi
