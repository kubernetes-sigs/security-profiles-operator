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

# shellcheck source=hack/lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

VERSION=1.8.0
# The checksum of the source archive of the tag, bump together with VERSION.
SHA256=b7a1e685f90f6a63ead0dd85d053694b222975da8d09c1a966041cff6f0055ff

DIR="libbpf-$VERSION"
ARCHIVE="$DIR.tar.gz"
trap 'rm -rf -- "$DIR" "$ARCHIVE"' EXIT

download_verified "https://github.com/libbpf/libbpf/archive/refs/tags/v$VERSION.tar.gz" \
    "$SHA256" "$ARCHIVE"
tar xfz "$ARCHIVE"

# libbpf installs into lib64 on every 64 bit architecture, which the linker
# does not search on arm64 Ubuntu. Use the library directory of the compiler.
LIBDIR=$(realpath -m "/usr/lib/$(gcc -print-multi-os-directory)")

make -C "$DIR/src" BUILD_STATIC_ONLY=y LIBDIR="$LIBDIR" \
    install install_uapi_headers -j8
