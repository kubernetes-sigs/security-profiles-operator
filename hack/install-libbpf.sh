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

VERSION=1.0.1
curl -sSfL --retry 5 --retry-delay 3 \
    "https://github.com/libbpf/libbpf/archive/refs/tags/v$VERSION.tar.gz" -o- |
    tar xfz -
pushd "libbpf-$VERSION/src"
make BUILD_STATIC_ONLY=y install
popd
rm -rf "libbpf-$VERSION"
