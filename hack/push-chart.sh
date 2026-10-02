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

# Packages the helm chart and pushes it as OCI artifact to
# $REGISTRY/charts/security-profiles-operator:<chart version>, signed as
# Sigstore bundle unless SIGN=false.
#
# Only -dev versions are pushed, they move with every build like the
# vX.Y.Z-dev image tags, and get a signature, SLSA provenance and an SBOM, see
# hack/attest-artifact.sh. Released versions are packaged and attested on
# GitHub and published from the release by hack/push-release-artifacts.sh, see
# doc/release.md#oci-artifacts.

set -euo pipefail

HACK_DIR="$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=hack/lib/common.sh
source "$HACK_DIR/lib/common.sh"

BUILD_DIR="${BUILD_DIR:-build}"
CHART_DIR="${CHART_DIR:-deploy/helm}"
REGISTRY="${REGISTRY:-us-central1-docker.pkg.dev/k8s-staging-images/sp-operator}"
HELM_VERSION=v3.22.0
HELM_SHA256=1e4ab49e429626cf6c6958d914248b78c9730803c2751b87627e171dc800e7bb
HELM="${HELM:-}"

REPO="$REGISTRY/charts"
CHART=security-profiles-operator

VERSION=$(sed -n 's/^version: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$CHART_DIR/Chart.yaml")
if [[ -z "$VERSION" ]]; then
  echo "Unable to read the chart version from $CHART_DIR/Chart.yaml" >&2
  exit 1
fi

if [[ "$VERSION" != *-dev ]]; then
  echo "Chart $VERSION is a release, it gets published from the GitHub release"
  exit 0
fi

HELM_DIR="$(mktemp -d)"
trap 'rm -rf "$HELM_DIR"' EXIT

# helm packages the chart, the provenance names the release archive it comes
# from, which is only known when it is downloaded here.
PROVENANCE_DEPENDENCIES="[]"
if [[ -z "$HELM" ]]; then
  HELM_URL="https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz"
  TARBALL="$HELM_DIR/helm.tar.gz"
  curl -sSfL --retry 5 --retry-delay 3 -o "$TARBALL" "$HELM_URL"
  echo "$HELM_SHA256  $TARBALL" | sha256sum -c -
  tar xzf "$TARBALL" -C "$HELM_DIR" --strip-components=1 linux-amd64/helm
  HELM="$HELM_DIR/helm"
  PROVENANCE_DEPENDENCIES="$(file_dependency helm "$TARBALL" "$HELM_URL" | "$(jq_bin)" -cs .)"
fi
export PROVENANCE_DEPENDENCIES

# Without a password helm uses the Docker configuration, see registry_login in
# hack/lib/common.sh.
if [[ -n "${PASSWORD:-}" ]]; then
  printf '%s' "$PASSWORD" |
    "$HELM" registry login "${REGISTRY%%/*}" -u "${USERNAME:-oauth2accesstoken}" --password-stdin
fi

mkdir -p "$BUILD_DIR"
"$HELM" package -d "$BUILD_DIR" "$CHART_DIR"
PACKAGE="$BUILD_DIR/$CHART-$VERSION.tgz"

echo "Pushing chart $VERSION to oci://$REPO"
OUTPUT=$("$HELM" push "$PACKAGE" "oci://$REPO" 2>&1)
echo "$OUTPUT"

DIGEST=$(sed -n 's/^Digest: *\(sha256:[a-f0-9]\{64\}\)$/\1/p' <<<"$OUTPUT")
if [[ -z "$DIGEST" ]]; then
  echo "Unable to read the chart digest from the helm push output" >&2
  exit 1
fi

"$HACK_DIR/sign-images.sh" "$REPO/$CHART@$DIGEST"
"$HACK_DIR/attest-artifact.sh" "$REPO/$CHART@$DIGEST" "$PACKAGE"
