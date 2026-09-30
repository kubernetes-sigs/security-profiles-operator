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

VERSION=1.7.0
# The checksum of the source archive of the tag, bump together with VERSION.
SHA256=7ab5feffbf78557f626f2e3e3204788528394494715a30fc2070fcddc2051b7b

DIR="libbpf-$VERSION"
ARCHIVE="$DIR.tar.gz"
trap 'rm -rf -- "$DIR" "$ARCHIVE"' EXIT

curl -sSfL --retry 5 --retry-delay 3 -o "$ARCHIVE" \
    "https://github.com/libbpf/libbpf/archive/refs/tags/v$VERSION.tar.gz"
echo "$SHA256  $ARCHIVE" | sha256sum -c -
tar xfz "$ARCHIVE"

# libbpf installs into lib64 on every 64 bit architecture, which the linker
# does not search on arm64 Ubuntu. Use the library directory of the compiler.
LIBDIR=$(realpath -m "/usr/lib/$(gcc -print-multi-os-directory)")

make -C "$DIR/src" BUILD_STATIC_ONLY=y LIBDIR="$LIBDIR" \
    install install_uapi_headers -j8
