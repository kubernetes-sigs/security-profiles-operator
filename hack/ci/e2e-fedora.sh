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
# These are already tested in the standard e2e test.
# No need to test them here.
export E2E_TEST_SECCOMP=false

# The SELinux tests restart the spod with SELinux support many times, which
# takes about a minute each, so CI runs them in a VM of their own.
case ${E2E_FEDORA_SUITE:-enricher} in
enricher)
  export E2E_TEST_SELINUX=false
  export E2E_TEST_BPF_RECORDER=false
  export E2E_TEST_LOG_ENRICHER=true
  export E2E_TEST_JSON_ENRICHER=true
  ;;
selinux)
  # The VM runs SELinux enforcing with CRI-O's SELinux support enabled, so
  # this is the only CI job that can run the SELinux tests.
  export E2E_TEST_SELINUX=true
  # The Fedora kernel provides the BTF the BPF recorder needs. It records
  # seccomp profiles independent of E2E_TEST_SECCOMP, which only gates the
  # tests of installing profiles.
  export E2E_TEST_BPF_RECORDER=true
  # The SELinux recording and the profile merging tests record through it.
  export E2E_TEST_LOG_ENRICHER=true
  export E2E_TEST_JSON_ENRICHER=false
  # Running the SELinux tests for the namespaced operator as well does not
  # fit into the test timeout. The enricher suite covers the namespaced
  # operator.
  export E2E_SKIP_NAMESPACED_TESTS=true
  # The enricher suite runs these as well, and with SELinux support each
  # restart of the spod takes about a minute.
  E2E_TEST_SKIP='//cluster-wide:_(Log_Enricher|SPOD:_(Change|Enable|Profiling)'
  E2E_TEST_SKIP+='|Seccomp:_Verify_profile_recording_logs)'
  export E2E_TEST_SKIP
  ;;
*)
  echo "Unknown E2E_FEDORA_SUITE: $E2E_FEDORA_SUITE" >&2
  exit 1
  ;;
esac

# CI builds selinuxd for the Fedora release of the VM outside of it, see
# hack/ci/build-selinuxd-fedora.sh.
export E2E_SELINUXD_IMAGE=localhost/selinuxd-fedora:latest

if "$E2E_TEST_SELINUX" && ! podman image exists "$E2E_SELINUXD_IMAGE"; then
  if [[ -f selinuxd-fedora.tar ]]; then
    podman load -i selinuxd-fedora.tar
  else
    hack/ci/build-selinuxd-fedora.sh "$E2E_SELINUXD_IMAGE"
  fi
fi

# CI compiles the tests outside of the VM, see E2E_TEST_BINARY in the Makefile.
# The artifact download loses the executable bit.
if [[ -f build/e2e.test ]]; then
  chmod +x build/e2e.test
  export E2E_TEST_BINARY=build/e2e.test
fi

export E2E_TEST_FLAKY_TESTS_ONLY=${E2E_TEST_FLAKY_TESTS_ONLY:-false}

if "${E2E_TEST_FLAKY_TESTS_ONLY}"; then
  make test-flaky-e2e
else
  make test-e2e
fi
