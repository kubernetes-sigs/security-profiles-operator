# Copyright 2020 The Kubernetes Authors.
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

FROM k8s.gcr.io/build-image/debian-base:buster-v1.4.0 AS build
WORKDIR /work

RUN apt-get update && apt-get install -y wget xz-utils

ARG NIX_VERSION=2.3.10
RUN wget https://nixos.org/releases/nix/nix-${NIX_VERSION}/nix-${NIX_VERSION}-$(uname -m)-linux.tar.xz && \
    tar xf nix-${NIX_VERSION}-$(uname -m)-linux.tar.xz && \
    groupadd -r -g 30000 nixbld && \
    for i in $(seq 1 30); do useradd -rM -u $((30000 + i)) -G nixbld nixbld$i ; done && \
    mkdir -m 0755 /etc/nix && \
    printf "sandbox = false\nfilter-syscalls = false\n" > /etc/nix/nix.conf && \
    mkdir -m 0755 /nix && \
    USER=root sh nix-${NIX_VERSION}-$(uname -m)-linux/install && \
    ln -s /nix/var/nix/profiles/default/etc/profile.d/nix.sh /etc/profile.d

ENV ENV=/etc/profile \
    USER=root \
    PATH=/nix/var/nix/profiles/default/bin:/nix/var/nix/profiles/default/sbin:/bin:/sbin:/usr/bin:/usr/sbin \
    GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt \
    NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    NIX_PATH=/nix/var/nix/profiles/per-user/root/channels

COPY . /work

FROM build as make

RUN nix-env -iA cachix -f https://cachix.org/api/v1/install
RUN cachix use security-profiles-operator

ARG target=nix
RUN nix-build $target

FROM scratch
ARG version

LABEL name="Security Profiles Operator" \
      version=$version \
      description="The Security Profiles Operator makes it easier for cluster admins to manage their seccomp or AppArmor profiles and apply them to Kubernetes' workloads."

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=make /work/result/security-profiles-operator /

USER 65535:65535

ENTRYPOINT ["/security-profiles-operator"]
