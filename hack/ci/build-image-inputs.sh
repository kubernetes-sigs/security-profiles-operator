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

# The inputs of the toolchain image of Dockerfile.build-image, as an extended
# regular expression for the changed file names: the Dockerfile, its build
# context, the nix expressions whose dependencies it caches, and the build
# workflow with the scripts of its build-image job, which define how the image
# gets built, tagged, signed and attested. code-changed.sh builds the image
# when they change, build-image-tags.sh moves its floating tags only while no
# later commit changes them. Source this file.

# The scripts sourcing this file use it.
# shellcheck disable=SC2034
BUILD_IMAGE_INPUTS='^(Dockerfile\.build-image|\.dockerignore|flake\.nix|flake\.lock|nix/|\.github/workflows/build\.yml|hack/ci/build-image-(inputs|tags)\.sh)'
