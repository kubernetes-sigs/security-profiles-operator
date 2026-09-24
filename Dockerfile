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
ARG BUILD_IMAGE=quay.io/security-profiles-operator/build@sha256:4eb34d389b920396114362cdf2ad8a56cb6e95cc471295ec40f9faf9d1a9a188

# The build stages run on the build platform, nix cross compiles for the target.
FROM --platform=$BUILDPLATFORM $BUILD_IMAGE AS build

COPY . /work

FROM build AS make

ARG target=default
# The binaries are always built from source. Only their dependencies (the
# inputDerivation closure) may come from the binary caches, so that a poisoned
# cache entry cannot stand in for them.
RUN nix build path:.#$target.inputDerivation --no-link --extra-experimental-features 'nix-command flakes' && \
  nix build path:.#$target --option substitute false --extra-experimental-features 'nix-command flakes'

FROM scratch
ARG version

LABEL name="Security Profiles Operator" \
      version=$version \
      description="The Security Profiles Operator makes it easier for cluster admins to manage their SELinux, seccomp and AppArmor profiles and apply them to Kubernetes' workloads."

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=make /work/result/security-profiles-operator /
COPY --from=make /work/result/spoc /

USER 65535:65535
ENV PATH=/

ENTRYPOINT ["/security-profiles-operator"]
