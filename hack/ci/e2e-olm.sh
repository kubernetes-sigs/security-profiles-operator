#!/usr/bin/env bash
# Copyright 2021 The Kubernetes Authors.
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

set -x

OLM_VERSION=v0.18.2

REPO=localhost:5000
IMG=${REPO}/security-profiles-operator:${GITHUB_SHA}
BUNDLE_IMG=${REPO}/security-profiles-operator-bundle:v${GITHUB_SHA}
CATALOG_IMG=${REPO}/security-profiles-operator-catalog:v${GITHUB_SHA}

function build_and_push_spo() {
    make image IMAGE=${IMG}
    podman push --tls-verify=false ${IMG}
}

function build_and_push_packages() {
    OPERATOR_MANIFEST=deploy/operator-ci.yaml

    # Create a manifest with local image
    pushd deploy/base
    kustomize edit set image security-profiles-operator=$IMG
    popd
    kustomize build --reorder=none deploy/overlays/cluster -o ${OPERATOR_MANIFEST}

    # this is a kludge, we need to make sure kustomize can be overwritten
    rm -f build/kustomize

    # create bundle, bundle image, push bundle using our manifest created earlier
    make bundle BUNDLE_OPERATOR_MANIFEST=${OPERATOR_MANIFEST}
    # GH CI workers have pretty limited CPU and won't be able to run SPO, OLM and cert-manager at the same time
    sed -i '/cpu\:/d' bundle/manifests/security-profiles-operator.clusterserviceversion.yaml
    make bundle-build BUNDLE_IMG=${BUNDLE_IMG}
    podman push --tls-verify=false ${BUNDLE_IMG}

    # create catalog image, push catalog
    make catalog-build OPM_EXTRA_ARGS=" --skip-tls" BUNDLE_IMGS=${BUNDLE_IMG} CATALOG_IMG=${CATALOG_IMG}
    podman push --tls-verify=false ${CATALOG_IMG}
}

function deploy_olm() {
    operator-sdk olm install --version ${OLM_VERSION} --timeout 6m
}

function deploy_spo() {
    # cert-manager first. This should be done using dependencies in the
    # future
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml
    kubectl -ncert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

    # let's roll..
    sed -i "s#k8s.gcr.io/security-profiles-operator/security-profiles-operator-catalog:v0.4.3#${CATALOG_IMG}#g" examples/olm/install-resources.yaml
    kubectl create -f examples/olm/install-resources.yaml
}

function check_spo_is_running() {
    # Useful in case the CatalogSource is fubar. We retry several times
    # because on transient errors (which are for some reason common even
    # if the catalog is local) the pod gets restarted
    for i in $(seq 1 5); do
        kubectl -nolm wait --for=condition=ready pods -lolm.catalogSource=security-profiles-operator
        catalog_logs=$(kubectl -nolm logs $(kubectl -nolm get pods --no-headers -lolm.catalogSource=security-profiles-operator | awk '{print $1}') 2>/dev/null)
        if [[ -n "$catalog_logs" ]]; then
            echo $catalog_logs
            break
        fi
    done

    # wait a bit for CSV to appear
    # (jhrozek): I didn't find a useful condition or status to wait for..
    # ..if only there was a way to check if ANY installedCSV is set..
    sleep 30
    CSV=$(kubectl -nsecurity-profiles-operator get sub security-profiles-operator-sub -ojsonpath='{.status.installedCSV}')
    # wait for the CSV to be actually installed
    kubectl -nsecurity-profiles-operator wait --for=jsonpath='{.status.phase}'=Succeeded csv $CSV

    # wait for the operator to be ready
    kubectl -nsecurity-profiles-operator wait --for=condition=ready pod -lname=security-profiles-operator
    kubectl -nsecurity-profiles-operator wait --for=condition=ready pod -lname=security-profiles-operator-webhook

    # wait for spod pod to be created, kubectl wait for un-existed resource seems to exit with error
    # which is causing random test failure
    # see https://github.com/kubernetes/kubernetes/issues/83242
    for i in $(seq 1 10); do
        found=$(kubectl get -nsecurity-profiles-operator pods -lname=spod 2>/dev/null)
        if [[ $found ]]; then
            break
        fi
        sleep 5
    done
    kubectl -nsecurity-profiles-operator wait --for=condition=ready pod -lname=spod
}

# The actual script begins here
build_and_push_spo
build_and_push_packages
deploy_olm
deploy_spo
check_spo_is_running
