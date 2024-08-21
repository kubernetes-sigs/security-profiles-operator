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

# to pin base image below may require further changes on build/release processes
FROM quay.io/security-profiles-operator/build:latest AS build

COPY . /work

FROM build AS make

ARG target=nix
RUN nix-build $target

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
