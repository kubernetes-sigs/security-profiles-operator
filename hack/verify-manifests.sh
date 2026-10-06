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

# Validates the committed manifests and the examples with kubeconform against
# the schemas of KUBERNETES_VERSION and of the CRDs in this tree, and lints the
# operator deployments with kube-linter, see .kube-linter.yaml. The tools run
# with go run, the module checksum database verifies them.

set -euo pipefail

GO="${GO:-go}"
BUILD_DIR="${BUILD_DIR:-build}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:?KUBERNETES_VERSION must be set}"
: "${KUBECONFORM_VERSION:?KUBECONFORM_VERSION must be set}"
: "${KUBE_LINTER_VERSION:?KUBE_LINTER_VERSION must be set}"
: "${YQ_VERSION:?YQ_VERSION must be set}"

cd "$(git rev-parse --show-toplevel)"

run() {
  GOFLAGS='' CGO_ENABLED=0 "$GO" run "$@"
}

yq() {
  run "github.com/mikefarah/yq/v4@v$YQ_VERSION" "$@"
}

# kubeconform needs JSON schemas named after the kind, group and version.
SCHEMAS="$BUILD_DIR/crd-schemas"
# The kind, group and version of every version of a CRD, tab separated.
# shellcheck disable=SC2016 # a yq expression, not a shell one
CRD_VERSIONS='.spec as $spec | $spec.versions[] | [$spec.names.kind, $spec.group, .name] | @tsv'
rm -rf "$SCHEMAS"
mkdir -p "$SCHEMAS"
for crd in deploy/base-crds/crds/*.yaml; do
  while IFS=$'\t' read -r kind group version; do
    # Files with several CRDs print document separators in between.
    [[ -n "$version" ]] || continue
    yq -o=json \
      "select(.spec.names.kind == \"$kind\") | .spec.versions[] | select(.name == \"$version\") | .schema.openAPIV3Schema" \
      "$crd" >"$SCHEMAS/${kind,,}-$group-$version.json"
  done < <(yq "$CRD_VERSIONS" "$crd")
done

echo "Validating the manifests against Kubernetes $KUBERNETES_VERSION"
# The OpenShift kinds and the CRDs themselves have no schema here and get
# skipped.
run "github.com/yannh/kubeconform/cmd/kubeconform@$KUBECONFORM_VERSION" \
  -strict \
  -summary \
  -ignore-missing-schemas \
  -kubernetes-version "$KUBERNETES_VERSION" \
  -schema-location default \
  -schema-location "$SCHEMAS/{{.ResourceKind}}-{{.Group}}-{{.ResourceAPIVersion}}.json" \
  deploy/operator.yaml \
  deploy/namespace-operator.yaml \
  deploy/webhook-operator.yaml \
  deploy/openshift-dev.yaml \
  deploy/openshift-downstream.yaml \
  deploy/helm/crds/crds.yaml \
  examples/*.yaml \
  examples/olm/*.yaml \
  hack/ci/apparmorprofile-sleep-*.yaml

echo "Linting the operator deployments"
run "golang.stackrox.io/kube-linter/cmd/kube-linter@$KUBE_LINTER_VERSION" lint \
  --config .kube-linter.yaml \
  deploy/operator.yaml \
  deploy/namespace-operator.yaml \
  deploy/webhook-operator.yaml
