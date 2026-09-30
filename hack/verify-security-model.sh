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

# Verifies that doc/security-model.md names the security profiles the
# operator applies to its own containers, and the API groups of each role in
# deploy/base/role.yaml in the section of that role.

set -euo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)
cd "$GIT_ROOT"

DOC=doc/security-model.md
ROLES=deploy/base/role.yaml

rc=0

fail() {
  echo "$DOC: $*" >&2
  rc=1
}

# go_const prints the value of the string constant of the Go file.
go_const() {
  local file=$1 name=$2 value
  value=$(sed -nE "s/^[[:space:]]*${name}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "$file")
  if [[ -z $value ]]; then
    echo "$file: constant $name not found" >&2
    exit 1
  fi
  echo "$value"
}

profiles=(
  "$(go_const internal/pkg/config/config.go SpoApparmorProfileName)"
  "$(go_const internal/pkg/config/config.go BpfRecorderApparmorProfileName)"
  "$(go_const internal/pkg/manager/spod/bindata/spod.go LocalSeccompProfilePath)"
  "$(go_const internal/pkg/manager/spod/bindata/spod.go LocalSeccompBpfRecorderProfilePath)"
)

for profile in "${profiles[@]}"; do
  if ! grep -qF "\`$profile\`" "$DOC"; then
    fail "the security profile \`$profile\` is not documented"
  fi
done

# role_groups prints the role name and API group of each rule of the Roles
# and ClusterRoles, separated by a space. The core group and the API group of
# the operator itself are left out.
role_groups() {
  awk '
    /^---/ { name = ""; section = "" }
    /^metadata:/ { section = "metadata"; next }
    /^rules:/ { section = "rules"; next }
    section == "metadata" && /^  name:/ { name = $2 }
    section == "rules" && /^- apiGroups:/ { groups = 1; next }
    section == "rules" && groups && /^  - / {
      group = $2
      gsub(/"/, "", group)
      if (group != "" && group != "security-profiles-operator.x-k8s.io") {
        print name, group
      }
      next
    }
    /^  [a-zA-Z]/ { groups = 0 }
  ' "$ROLES" | sort -u
}

# role_section prints the section of the role in the documentation, up to the
# next heading.
role_section() {
  awk -v heading="### $1" '
    $0 == heading { found = 1; next }
    found && /^#/ { exit }
    found { print }
  ' "$DOC"
}

roles_checked=0
while read -r role group; do
  roles_checked=$((roles_checked + 1))
  section=$(role_section "$role")
  if [[ -z $section ]]; then
    fail "no section \"### $role\" for the role $role of $ROLES"
    continue
  fi
  if ! grep -qF "\`$group\`" <<<"$section"; then
    fail "the section of the role $role does not name its API group \`$group\`"
  fi
done < <(role_groups)

if ((roles_checked == 0)); then
  echo "$ROLES: no API groups found, the parser needs an update" >&2
  exit 1
fi

if ((rc == 0)); then
  echo "$DOC matches the security profiles and the roles"
fi

exit "$rc"
