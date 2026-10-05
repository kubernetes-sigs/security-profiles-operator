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

if [ $# -eq 0 ]; then
    echo "No release version provided"
    exit 1
fi

# GNU and BSD sed differ in how -i takes the backup suffix.
sed_i() {
    if sed --version >/dev/null 2>&1; then
        sed -i "$@"
    else
        sed -i '' "$@"
    fi
}

GIT_ROOT=$(git rev-parse --show-toplevel)
pushd "$GIT_ROOT" >/dev/null

VERSION=${1#v}

echo "Using version $VERSION"

# Change VERSION file
PREVIOUS_VERSION=$(cat VERSION)
echo "$VERSION" >VERSION

# Update base kustomization
FILE=deploy/kustomize-deployment/kustomization.yaml
sed_i 's;newName: us-central1-docker.pkg.dev;# newName: us-central1-docker.pkg.dev;g' $FILE
sed_i 's;newTag: latest;# newTag: latest;g' $FILE
sed_i 's;# newName: registry.k8s.io;newName: registry.k8s.io;g' $FILE
sed_i 's;# newTag: v.*;newTag: v'"$VERSION"';g' $FILE

# Update exaxmples
sed_i 's;image: .*;image: registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"$VERSION"';g' examples/olm/install-resources.yaml

# Update e2e tests
# shellcheck disable=SC2016
sed_i 's;us-central1-docker.pkg.dev.*catalog.*;registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"$VERSION"'#${CATALOG_IMG}#g" examples/olm/install-resources.yaml;g' hack/ci/e2e-olm.sh
sed_i 's;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/;registry.k8s.io/;g' hack/ci/e2e-olm.sh
sed_i 's;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/;registry.k8s.io/;g' test/e2e_test.go
# The base profile artifacts are promoted under the project name.
sed_i 's;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/base/;registry.k8s.io/security-profiles-operator/base/;g' test/tc_base_profiles_oci_runtime_test.go

# Update patches
sed_i 's;us-central1-docker.pkg.dev.*;registry.k8s.io/security-profiles-operator/security-profiles-operator:v'"$VERSION"';g' hack/deploy-localhost.patch

# Update webhook overlay
FILE=deploy/overlays/webhook/kustomization.yaml
sed_i 's;newName: us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator;newName: registry.k8s.io/security-profiles-operator/security-profiles-operator;g' $FILE
sed_i 's;newTag: latest;newTag: v'"$VERSION"';g' $FILE

# Update Helm chart values to use release image
FILE=deploy/helm/values.yaml
sed_i 's;registry: us-central1-docker.pkg.dev;registry: registry.k8s.io;g' $FILE
sed_i 's;repository: k8s-staging-images/sp-operator/security-profiles-operator;repository: security-profiles-operator/security-profiles-operator;g' $FILE
sed_i '0,/tag: latest/{s;tag: latest;tag: v'"$VERSION"';}' $FILE
sed_i 's;pullPolicy: Always;pullPolicy: IfNotPresent;g' $FILE

# The Helm chart README documents the same defaults
FILE=deploy/helm/README.md
sed_i \
    -e 's;^\(| spoImage.pullPolicy | string | `\)"Always";\1"IfNotPresent";' \
    -e 's;^\(| spoImage.registry | string | `\)"us-central1-docker.pkg.dev";\1"registry.k8s.io";' \
    -e 's;^\(| spoImage.repository | string | `\)"k8s-staging-images/sp-operator/security-profiles-operator";\1"security-profiles-operator/security-profiles-operator";' \
    -e 's;^\(| spoImage.tag | string | `\)"latest";\1"v'"$VERSION"'";' \
    $FILE

# Update dependencies.yaml
PREVIOUS_VERSION_RE="${PREVIOUS_VERSION//./\\.}"
FILES=(
    dependencies.yaml
    deploy/helm/Chart.yaml
    deploy/helm/README.md
    doc/installation.md
)
for FILE in "${FILES[@]}"; do
    sed_i "s;$PREVIOUS_VERSION_RE;$VERSION;g" "$FILE"
done

# Update the versioned install manifests and the spoc image and version.
sed_i -E "s;(raw\.githubusercontent\.com/kubernetes-sigs/security-profiles-operator/v)[0-9]+\.[0-9]+\.[0-9]+/;\1$VERSION/;g" doc/installation.md
sed_i -E \
    -e "s;(security-profiles-operator/security-profiles-operator:v)[0-9]+\.[0-9]+\.[0-9]+;\1$VERSION;g" \
    -e "s;^(   v)[0-9]+\.[0-9]+\.[0-9]+\$;\1$VERSION;" \
    doc/cli.md

# Fix shields.io badge URL encoding (-- represents literal -)
PREVIOUS_BADGE="${PREVIOUS_VERSION//-/--}"
if [ "$PREVIOUS_BADGE" != "$PREVIOUS_VERSION" ]; then
    PREVIOUS_BADGE_RE="${PREVIOUS_BADGE//./\\.}"
    VERSION_BADGE="${VERSION//-/--}"
    sed_i "s;$PREVIOUS_BADGE_RE;$VERSION_BADGE;g" deploy/helm/README.md
fi

# Update operatorhub replacement
FILE=deploy/base/clusterserviceversion.yaml
OPERATOR_VERSION=$(curl -sSfL --retry 5 --retry-delay 3 "https://operatorhub.io/api/operator?packageName=security-profiles-operator" |
    jq -r .operator.name)
sed_i 's;replaces:.*;replaces: '"$OPERATOR_VERSION"';g' $FILE
sed_i 's;containerImage:.*;containerImage: registry.k8s.io/security-profiles-operator/security-profiles-operator:v'"$VERSION"';g' $FILE

# Stage the sources, because `make bundle` will use `git restore`
git add .

# Build bundle
make bundle

git add .

echo "Done. Commit the changes to a new branch and create a PR from it"
