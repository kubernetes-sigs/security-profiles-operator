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

GIT_ROOT=$(git rev-parse --show-toplevel)
pushd "$GIT_ROOT" >/dev/null

VERSION=$(cat VERSION)
VERSION_MAJOR=$(echo "$VERSION" | cut -d. -f1)
VERSION_MINOR=$(echo "$VERSION" | cut -d. -f2)
VERSION_PATCH=$(echo "$VERSION" | cut -d. -f3 | cut -d- -f1)
NEXT_VERSION="$VERSION_MAJOR.$VERSION_MINOR.$((VERSION_PATCH + 1))"
DEV_VERSION="$NEXT_VERSION-dev"

echo "Bumping current version '$VERSION' back to development version '$DEV_VERSION'"

echo "$DEV_VERSION" >VERSION

VERSION_RE="${VERSION//./\\.}"
sed -i \
    -e "s;image: registry.k8s.io/security-profiles-operator/security-profiles-operator.*;image: us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest;g" \
    -e "s/$VERSION_RE/$DEV_VERSION/g" \
    deploy/namespace-operator.yaml \
    deploy/openshift-downstream.yaml \
    deploy/operator.yaml \
    deploy/webhook-operator.yaml

sed -i \
    -e 's;\(olm.skipRange.*\)'"$VERSION_RE"';\1'"$DEV_VERSION"';g' \
    -e 's;\(name: security-profiles-operator.v\)'"$VERSION_RE"';\1'"$DEV_VERSION"';g' \
    -e 's;\(version: \)'"$VERSION_RE"';\1'"$DEV_VERSION"';g' \
    -e 's;image: registry.k8s.io/security-profiles-operator/security-profiles-operator.*;image: us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest;g' \
    -e 's;containerImage: registry.k8s.io/security-profiles-operator/security-profiles-operator.*;containerImage: us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest;g' \
    bundle/manifests/security-profiles-operator.clusterserviceversion.yaml

sed -i "s;registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog.*;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-catalog:latest;g" \
    examples/olm/install-resources.yaml

sed -i "s;image: registry.k8s.io/security-profiles-operator/security-profiles-operator.*;image: image-registry.openshift-image-registry.svc:5000/openshift/security-profiles-operator:latest;g" \
    deploy/openshift-dev.yaml

sed -i "s/$VERSION_RE/$DEV_VERSION/g" \
    dependencies.yaml \
    deploy/catalog-preamble.json \
    deploy/helm/Chart.yaml \
    deploy/helm/README.md

# Fix shields.io badge URL encoding (-- represents literal -)
DEV_BADGE="${DEV_VERSION//-/--}"
if [ "$DEV_BADGE" != "$DEV_VERSION" ]; then
    DEV_VERSION_RE="${DEV_VERSION//./\\.}"
    sed -i "s;${DEV_VERSION_RE}-informational;${DEV_BADGE}-informational;g" deploy/helm/README.md
fi

sed -i \
    -e 's;# \(newName: .*\);\1;g' \
    -e 's;# \(newTag: .*\);\1;g' \
    -e 's;\(newName: registry.k8s.io/.*\);# \1;g' \
    -e 's;\(newTag: \)v'"$VERSION"';# \1'"v$NEXT_VERSION"';g' \
    deploy/kustomize-deployment/kustomization.yaml

sed -i \
    -e 's;registry.k8s.io/security-profiles-operator/security-profiles-operator-catalog:v'"$VERSION"';us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator-catalog:latest;g' \
    -e 's;registry.k8s.io;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator;g' \
    hack/ci/e2e-olm.sh

sed -i 's;registry.k8s.io;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator;g' test/e2e_test.go
sed -i 's;registry.k8s.io/security-profiles-operator/base/;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/base/;g' test/tc_base_profiles_oci_runtime_test.go

sed -i 's;registry.k8s.io/security-profiles-operator.*;us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator:latest;g' \
    hack/deploy-localhost.patch

# Revert webhook overlay to staging
sed -i \
    -e 's;newName: registry.k8s.io/security-profiles-operator/security-profiles-operator;newName: us-central1-docker.pkg.dev/k8s-staging-images/sp-operator/security-profiles-operator;g' \
    -e 's;newTag: v'"$VERSION"';newTag: latest;g' \
    deploy/overlays/webhook/kustomization.yaml

# Revert Helm chart values to staging
sed -i \
    -e 's;registry: registry.k8s.io;registry: us-central1-docker.pkg.dev;g' \
    -e 's;repository: security-profiles-operator/security-profiles-operator;repository: k8s-staging-images/sp-operator/security-profiles-operator;g' \
    -e 's;tag: v'"$VERSION"';tag: latest;g' \
    -e 's;pullPolicy: IfNotPresent;pullPolicy: Always;g' \
    deploy/helm/values.yaml

echo "Done. Commit the changes to a new branch and create a PR from it"
