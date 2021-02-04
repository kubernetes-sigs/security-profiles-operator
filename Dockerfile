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

FROM golang:1.15.7-alpine AS build
WORKDIR /work
RUN apk --no-cache add build-base git gcc libseccomp-dev libseccomp-static

COPY . /work

FROM build as make
RUN make

FROM scratch
ARG version

LABEL name="Security Profiles Operator" \
      version=$version \
      description="The Security Profiles Operator makes it easier for cluster admins to manage their seccomp or AppArmor profiles and apply them to Kubernetes' workloads."

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=make /work/build/security-profiles-operator /

USER 65535:65535

ENTRYPOINT ["/security-profiles-operator"]
