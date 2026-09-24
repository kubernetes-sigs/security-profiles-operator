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

# Print the Go release to build with, without the "go" prefix. The toolchain
# directive of go.mod wins over the go directive. A two-component version
# ("1.28") is legal in go.mod but there is no go1.28 release, only go1.28.0, so
# the patch level is filled in.
set -euo pipefail

GO_MOD=${1:-$(dirname "$0")/../go.mod}

VERSION=$(sed -n 's;^toolchain[[:space:]]*go\([^[:space:]]*\).*;\1;p' "$GO_MOD")
if [ -z "$VERSION" ]; then
    VERSION=$(sed -n 's;^go[[:space:]][[:space:]]*\([^[:space:]]*\).*;\1;p' "$GO_MOD")
fi

if [ -z "$VERSION" ]; then
    echo "no go or toolchain directive found in $GO_MOD" >&2
    exit 1
fi

# Pre-releases like "1.28rc1" are complete release names already.
if [[ $VERSION =~ ^[0-9]+\.[0-9]+$ ]]; then
    VERSION="$VERSION.0"
fi

echo "$VERSION"
