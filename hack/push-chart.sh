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
# Released chart versions are pushed once and left alone afterwards, while
# -dev versions move with every build, like the vX.Y.Z-dev image tags.

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
CHART_DIR="${CHART_DIR:-deploy/helm}"
REGISTRY="${REGISTRY:-us-central1-docker.pkg.dev/k8s-staging-images/sp-operator}"
SKIP_EXISTING="${SKIP_EXISTING:-true}"
HELM_VERSION=v3.17.3
HELM_SHA256=ee88b3c851ae6466a3de507f7be73fe94d54cbf2987cbaa3d1a3832ea331f2cd
HELM="${HELM:-}"

REPO="$REGISTRY/charts"
CHART=security-profiles-operator

if [[ -z "$HELM" ]]; then
  HELM_DIR="$(mktemp -d)"
  trap 'rm -rf "$HELM_DIR"' EXIT
  TARBALL="$HELM_DIR/helm.tar.gz"
  curl -sSfL --retry 5 --retry-delay 3 -o "$TARBALL" \
    "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz"
  echo "$HELM_SHA256  $TARBALL" | sha256sum -c -
  tar xzf "$TARBALL" -C "$HELM_DIR" --strip-components=1 linux-amd64/helm
  HELM="$HELM_DIR/helm"
fi

if [[ -n "${PASSWORD:-}" ]]; then
  printf '%s' "$PASSWORD" |
    "$HELM" registry login "${REGISTRY%%/*}" -u "${USERNAME:-oauth2accesstoken}" --password-stdin
fi

VERSION=$(sed -n 's/^version: *"\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$CHART_DIR/Chart.yaml")
if [[ -z "$VERSION" ]]; then
  echo "Unable to read the chart version from $CHART_DIR/Chart.yaml" >&2
  exit 1
fi

# Only a missing chart is pushed, any other lookup error fails, so a released
# chart is never replaced because of a temporary registry error.
if [[ "$SKIP_EXISTING" == "true" && "$VERSION" != *-dev ]]; then
  if SHOW_OUTPUT=$("$HELM" show chart "oci://$REPO/$CHART" --version "$VERSION" 2>&1); then
    echo "Already published, skipping chart $VERSION"
    exit 0
  fi

  if ! grep -qiE 'not found|manifest unknown' <<<"$SHOW_OUTPUT"; then
    echo "Unable to check whether chart $VERSION exists:" >&2
    echo "$SHOW_OUTPUT" >&2
    exit 1
  fi
fi

mkdir -p "$BUILD_DIR"
"$HELM" package -d "$BUILD_DIR" "$CHART_DIR"

echo "Pushing chart $VERSION to oci://$REPO"
OUTPUT=$("$HELM" push "$BUILD_DIR/$CHART-$VERSION.tgz" "oci://$REPO" 2>&1)
echo "$OUTPUT"

DIGEST=$(sed -n 's/^Digest: *\(sha256:[a-f0-9]\{64\}\)$/\1/p' <<<"$OUTPUT")
if [[ -z "$DIGEST" ]]; then
  echo "Unable to read the chart digest from the helm push output" >&2
  exit 1
fi

"$(dirname "${BASH_SOURCE[0]}")/sign-images.sh" "$REPO/$CHART@$DIGEST"
"$(dirname "${BASH_SOURCE[0]}")/attest-provenance.sh" "$REPO/$CHART@$DIGEST"
