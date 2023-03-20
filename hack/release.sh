#!/usr/bin/env bash
# Copyright 2022 The Kubernetes Authors.
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

if [ $# -eq 0 ]; then
    echo "No release version provided"
    exit 1
fi

GIT_ROOT=$(git rev-parse --show-toplevel)
pushd "$GIT_ROOT" >/dev/null

VERSION=${1#v}

echo "Using version $VERSION"

# Change VERSION file
PREVIOUS_VERSION=$(cat VERSION)
echo "$VERSION" >VERSION

# Update base kustomization
FILE=deploy/kustomize-deployment/kustomization.yaml
sed -i 's;newName: gcr.io;# newName: gcr.io;g' $FILE
sed -i 's;newTag: latest;# newTag: latest;g' $FILE
sed -i 's;# newName: registry.k8s.io;newName: registry.k8s.io;g' $FILE
sed -i 's;# newTag: v.*;newTag: v'"$VERSION"';g' $FILE

# Update exaxmples
sed -i 's;image: .*;image: registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"$VERSION"';g' examples/olm/install-resources.yaml

# Update e2e tests
# shellcheck disable=SC2016
sed -i 's;gcr.io/k8s-staging-sp-operator.*;registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"$VERSION"'#${CATALOG_IMG}#g" examples/olm/install-resources.yaml;g' hack/ci/e2e-olm.sh
sed -i 's;gcr.io/k8s-staging-sp-operator/;registry.k8s.io/;g' test/e2e_test.go

# Update dependencies.yaml
FILES=(
    dependencies.yaml
    deploy/helm/Chart.yaml
    installation-usage.md
)
for FILE in "${FILES[@]}"; do
    sed -i "s;$PREVIOUS_VERSION;$VERSION;g" "$FILE"
done

# Update operatorhub replacement
FILE=deploy/base/clusterserviceversion.yaml
OPERATOR_VERSION=$(curl -sSfL --retry 5 --retry-delay 3 "https://operatorhub.io/api/operator?packageName=security-profiles-operator" |
    jq -r .operator.name)
sed -i 's;replaces:.*;replaces: '"$OPERATOR_VERSION"';g' $FILE
sed -i 's;containerImage:.*;containerImage: registry.k8s.io/security-profiles-operator/security-profiles-operator:v'"$VERSION"';g' $FILE

# Build bundle
make bundle

echo "Done. Commit the changes to a new branch and create a PR from it"
