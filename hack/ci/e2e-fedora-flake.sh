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

# These are already tested in the standard e2e test.
# No need to test them here.
export E2E_TEST_SECCOMP=false

# These are already tested in the fedora e2e test.
export E2E_TEST_SELINUX=false
export E2E_TEST_LOG_ENRICHER=false
export E2E_TEST_PROFILE_RECORDING=false

E2E_TEST_TAGS=flake make test-e2e
