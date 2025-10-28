#!/usr/bin/env bash
# Copyright 2025 The Kubernetes Authors.
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

# TODO: remove this script once the debian image (via golang:1.25 or higher) ships
# the fixed libelf version.
#
apt-get install -y \
    bzip2 \
    m4 \
    zlib1g-dev

VERSION=0.193
curl -sSfL --retry 5 --retry-delay 3 \
    "https://sourceware.org/elfutils/ftp/$VERSION/elfutils-$VERSION.tar.bz2" -o- |
    tar xfj -

DIR="elfutils-$VERSION"
trap 'rm -rf -- "$DIR"' EXIT

pushd "$DIR"
./configure --prefix=/usr
make install -j8
popd
