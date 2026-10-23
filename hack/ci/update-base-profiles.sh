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

# Merges the recordings of e2e-seccomp.sh for all architectures, one directory
# per architecture below the directory given as first argument, into the base
# profiles in examples. The published profile artifact is platform
# independent, so a single profile lists every recorded architecture and the
# union of their syscalls. Runtimes skip syscalls that do not exist on the
# architecture they run on. The syscalls of the committed profile are kept, a
# recording only adds to them: on the kernel of the runner, a runtime may
# leave out a syscall that it still needs on older kernels. The syscalls that no
# recording holds anymore get logged. Fails if the result differs from the
# committed profiles.
update_base_profiles() {
  local recordings=$1 runtime profile versions committed merged
  local files=()

  for runtime in runc crun; do
    profile=examples/baseprofile-$runtime.yaml
    files=("$recordings"/*/"$runtime".json)
    echo "Merging ${files[*]} into $profile"

    versions=$(jq -r .version "${files[@]}" | sort -u)
    if [[ $(wc -l <<<"$versions") != 1 ]]; then
      echo "Recorded different $runtime versions:"
      echo "$versions"
      exit 1
    fi

    committed=$(yq -o json -I 0 '.spec.syscalls // []' "$profile")
    merged=$(jq -sc --argjson committed "$committed" '{
      architectures: ([.[].architectures[]] | unique),
      syscalls: ([.[].syscalls[]] + $committed | group_by(.action) | map({
        action: .[0].action,
        names: ([.[].names[]] | unique)
      }))
    }' "${files[@]}")

    jq -rs --argjson committed "$committed" '
      [$committed[].names[]] - [.[].syscalls[].names[]] | unique | .[]
    ' "${files[@]}" | sed 's/^/Not recorded anymore: /'

    yq -i "
      .metadata.name = \"$runtime-v$versions\" |
      .spec.architectures = $(jq -c .architectures <<<"$merged") |
      .spec.syscalls = $(jq -c .syscalls <<<"$merged")
    " "$profile"

    echo "-----------------------"
    cat "$profile"
    echo "-----------------------"
  done

  # All profiles are regenerated, so the workflow may upload them for a commit.
  mkdir -p build
  touch build/merged

  # There is a weird phenomenon where we have a `runc` process
  # that uses `setns` to join the container mount namespace.
  # As a consequence, we sometimes get all the funny syscalls emitted
  # by the Go runtime, which we need to ignore.
  # The pattern matches whole list entries, so that syscalls which only start
  # with one of these names, like exit_group or epoll_pwait2, still count.
  echo "Diffing output while ignoring flaky syscalls"
  git diff --exit-code -U0 \
    -I '^ *- (rt_sigreturn|sched_yield|tgkill|exit|madvise|rt_sigprocmask|sigaltstack|epoll_pwait)$' \
    examples
}

# shellcheck source=hack/ci/install-spo.sh
. "$(dirname "$0")/install-spo.sh"
# shellcheck source=hack/ci/install-yq.sh
. "$(dirname "$0")/install-yq.sh"

install_yq
update_base_profiles "${1:-build/recordings}"
