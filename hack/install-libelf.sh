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

curl_retry() {
    curl -sSfL --retry 5 --retry-delay 3 "$@"
}

VERSION=0.185
URL="https://sourceware.org/elfutils/ftp/$VERSION/elfutils-$VERSION.tar.bz2"
TAR_FILE=elfutils.tar.bz2
KEY=12768A96795990107A0D2FDFFC57E3CCACD99A78

curl_retry "$URL" -o $TAR_FILE
curl_retry "$URL.sig" -o $TAR_FILE.sig

gpg --keyserver hkp://keys.gnupg.net --recv-keys $KEY
gpg --verify $TAR_FILE.sig $TAR_FILE

tar xfj $TAR_FILE
pushd "elfutils-$VERSION"

./configure
make install

popd
rm -rf "elfutils-$VERSION" $TAR_FILE $TAR_FILE.sig
