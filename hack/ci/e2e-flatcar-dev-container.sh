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

# shellcheck shell=bash

set -euo pipefail

dev() {
  # --tmpfs=/tmp:size=2G: Allocate 2GB tmpfs to accommodate large vendor dependencies during test runs
  systemd-nspawn -q -i /opt/bin/flatcar_developer_container.bin --bind=/:/hostfs --tmpfs=/tmp:size=2G "$@"
}

# systemd-nspawn does not pass the environment on, so the switches which the
# CI jobs set in hack/ci/env-flatcar.sh are forwarded explicitly. The
# artifacts directory is a path in the container, where / is below /hostfs.
dev --chdir=/hostfs/vagrant \
  --setenv=E2E_TEST_FLAKY_TESTS_ONLY="${E2E_TEST_FLAKY_TESTS_ONLY:-false}" \
  --setenv=E2E_ARTIFACTS_DIR="${E2E_ARTIFACTS_DIR:-}" \
  -- /hostfs/vagrant/hack/ci/e2e-flatcar.sh
