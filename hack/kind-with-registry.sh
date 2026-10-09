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

# desired cluster name; default is "kind"
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
KIND_IMG_TAG="${KIND_IMG_TAG:-}"

# The kind release of the e2e suite, with the SHA512 checksums of its binaries
# per platform, which test/suite_test.go has too. dependencies.yaml tracks them
# in both files, bump them together.
KIND_VERSION=v0.33.0
KIND_SHA512_linux_amd64=f58a029ef8dee72f7fcf0345a5731795de0745ee6c955efd24801ced8409395cd2a4dc0ca41663c43231a48e94a5375cd01e63bc37b4557bf708e9ce6703fffa
KIND_SHA512_linux_arm64=034585fbb3766f34c3cdbc127b145c76904073918e2af76e31a81349aa2c67979e35ab780cc4a1cb1dadc5df04ae3b9c2984c1b382f1cff6b4ee48b560b7f048
KIND_SHA512_darwin_amd64=5dccea9fd7fef0d5f5e8212bc4683389b13c4724b55057911da9d34bb6b605641e024affaa34b17b672ed22df4534cdcbc56a505a3078d6f17a10ac81fbd5f10
KIND_SHA512_darwin_arm64=443edbc6dac7bf44025e90dafe0c66fd6489ee37ed58c80647578b8fcdd39567f986389b4bf38a0de0529ba7415da9c5c2ef9860b0227f3708d30c586671869b
case "$(uname -s)-$(uname -m)" in
Linux-x86_64)
  KIND_PLATFORM=linux-amd64
  KIND_SHA512=$KIND_SHA512_linux_amd64
  ;;
Linux-aarch64)
  KIND_PLATFORM=linux-arm64
  KIND_SHA512=$KIND_SHA512_linux_arm64
  ;;
Darwin-x86_64)
  KIND_PLATFORM=darwin-amd64
  KIND_SHA512=$KIND_SHA512_darwin_amd64
  ;;
Darwin-arm64)
  KIND_PLATFORM=darwin-arm64
  KIND_SHA512=$KIND_SHA512_darwin_arm64
  ;;
*)
  echo "No kind $KIND_VERSION checksum for $(uname -s)-$(uname -m)" >&2
  exit 1
  ;;
esac

# The pinned kind goes into the PATH of this script, and of the later steps of
# a GitHub job, which load images into the cluster.
KIND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build/kind-$KIND_VERSION"
if [[ ! -x "$KIND_DIR/kind" ]]; then
  mkdir -p "$KIND_DIR"
  download="$(mktemp "$KIND_DIR/kind.XXXXXX")"
  trap 'rm -f "$download"' EXIT
  curl -sSfL --retry 5 --retry-delay 3 -o "$download" \
    "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-$KIND_PLATFORM"
  if command -v sha512sum >/dev/null; then
    echo "$KIND_SHA512  $download" | sha512sum -c -
  else
    echo "$KIND_SHA512  $download" | shasum -a 512 -c -
  fi
  chmod +x "$download"
  mv "$download" "$KIND_DIR/kind"
fi
export PATH="$KIND_DIR:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$KIND_DIR" >>"$GITHUB_PATH"
fi

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5000'
running="$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)"
if [ "${running}" != 'true' ]; then
  docker run \
    -d --restart=always -p "${reg_port}:5000" --name "${reg_name}" \
    registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
fi

kind version

KIND_ARGS=(create cluster --name "${KIND_CLUSTER_NAME}" --wait=5m --config=-)
if [[ -n "${KIND_IMG_TAG}" ]]; then
  KIND_ARGS+=(--image "kindest/node:${KIND_IMG_TAG}")
fi

# create a cluster with the local registry enabled in containerd
cat <<EOF | kind "${KIND_ARGS[@]}"
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:${reg_port}"]
EOF

# connect the registry to the cluster network
docker network connect "kind" "${reg_name}" || true

# Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
