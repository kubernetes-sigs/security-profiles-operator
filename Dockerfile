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

# Pinned by digest: a mutable tag here means the toolchain that compiles every
# released binary can be replaced remotely without any change in this repo, and
# the provenance would still verify. Bump together with the build image.
ARG BUILD_IMAGE=quay.io/security-profiles-operator/build@sha256:dc669ccf589a45079e01d3b7d0ed58a68e60492f62a2caf7acb25a7ca5cf412f

# The build stages run on the build platform, nix cross compiles for the target.
FROM --platform=$BUILDPLATFORM $BUILD_IMAGE AS build

COPY . /work

FROM build AS make

# Only cache.nixos.org may substitute anything, whatever the configuration of
# the build image says. Older build images use the project's Cachix cache,
# which CI jobs running repository code write to. The configuration is
# rewritten, so that no extra-substituters of it or of an included file
# survive, and every nix call passes the substituters again on top.
RUN rm -rf /etc/nix/cachix /etc/nix/nix.custom.conf /root/.config/nix && \
  printf '%s\n' \
    'sandbox = false' \
    'filter-syscalls = false' \
    'experimental-features = nix-command flakes' \
    'substituters = https://cache.nixos.org' \
    'trusted-substituters =' \
    'trusted-public-keys = cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=' \
    > /etc/nix/nix.conf

ARG target=default
ENV NIX_FLAGS="--option experimental-features nix-command --option extra-experimental-features flakes --option substituters https://cache.nixos.org --option trusted-public-keys cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
# The binaries are always built from source. Only their dependencies (the
# inputDerivation closure) may come from cache.nixos.org, so that a poisoned
# cache entry cannot stand in for them.
RUN nix build path:.#$target.inputDerivation --no-link $NIX_FLAGS && \
  nix build path:.#$target --option substitute false $NIX_FLAGS

# The Go SBOMs only know the Go modules, this one lists the C libraries the
# binaries link statically. The build image has neither bash nor jq, the
# script gets them from nixpkgs.
RUN nix shell --inputs-from path:. nixpkgs#bash nixpkgs#coreutils nixpkgs#jq $NIX_FLAGS \
  -c bash hack/native-sbom.sh security-profiles-operator-native /work/native-libraries.spdx.json $target

FROM scratch
ARG version
# The OCI image annotations, hack/image-cross.sh passes the values of the
# build. Keep them in sync with Dockerfile.ubi, hack/ci/dockerfile-drift.sh
# checks that.
ARG source=https://github.com/kubernetes-sigs/security-profiles-operator
ARG revision
ARG created

LABEL name="Security Profiles Operator" \
      version=$version \
      description="The Security Profiles Operator makes it easier for cluster admins to manage their SELinux, seccomp and AppArmor profiles and apply them to Kubernetes' workloads." \
      org.opencontainers.image.title="Security Profiles Operator" \
      org.opencontainers.image.description="The Security Profiles Operator makes it easier for cluster admins to manage their SELinux, seccomp and AppArmor profiles and apply them to Kubernetes' workloads." \
      org.opencontainers.image.source=$source \
      org.opencontainers.image.revision=$revision \
      org.opencontainers.image.version=$version \
      org.opencontainers.image.created=$created \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=make /work/result/security-profiles-operator /
COPY --from=make /work/result/spoc /
COPY --from=make /work/native-libraries.spdx.json /sbom/

USER 65535:65535
ENV PATH=/

ENTRYPOINT ["/security-profiles-operator"]
