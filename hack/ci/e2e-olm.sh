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

function sp_in_ns() {
    ns=$1
kubectl create -f - << EOF
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log-all
  namespace: $ns
spec:
  defaultAction: "SCMP_ACT_LOG"
EOF
}

function build_and_push_spo() {
    make image IMAGE=${IMG}
    podman push --tls-verify=false ${IMG}
}

function build_and_push_packages() {
    OPERATOR_MANIFEST=deploy/operator-ci.yaml

    # Create a manifest with local image
    cp deploy/operator.yaml ${OPERATOR_MANIFEST}
    sed -i "s#gcr.io/k8s-staging-sp-operator/security-profiles-operator.*\$#${IMG}#" ${OPERATOR_MANIFEST}
    grep ${IMG} ${OPERATOR_MANIFEST} || exit 1

    # this is a kludge, we need to make sure kustomize can be overwritten
    rm -f build/kustomize

    # create bundle, bundle image, push bundle using our manifest created earlier
    make bundle BUNDLE_OPERATOR_MANIFEST=${OPERATOR_MANIFEST}
    # GH CI workers have pretty limited CPU and won't be able to run SPO, OLM and cert-manager at the same time
    sed -i '/cpu\:/d' bundle/manifests/security-profiles-operator.clusterserviceversion.yaml
    make bundle-build BUNDLE_IMG=${BUNDLE_IMG}
    podman push --tls-verify=false ${BUNDLE_IMG}

    # create catalog image, push catalog
    make catalog-build OPM_EXTRA_ARGS=" --use-http" BUNDLE_IMGS=${BUNDLE_IMG} CATALOG_IMG=${CATALOG_IMG}
    podman push --tls-verify=false ${CATALOG_IMG}
}

function deploy_deps() {
    # we need OLM
    operator-sdk olm install --version ${OLM_VERSION} --timeout 6m

    # cert-manager first. This should be done using dependencies in the
    # future
    kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
    kubectl -ncert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

    # All installation methods run off the same catalog
    sed -i "s#gcr.io/k8s-staging-sp-operator/security-profiles-operator-catalog:latest#${CATALOG_IMG}#g" examples/olm/install-resources.yaml

}

function deploy_spo_in_custom_ns() {
    ns=$1
    manifests=examples/olm/custom-install-resources.yaml

cat << EOF > $manifests
---
apiVersion: v1
kind: Namespace
metadata:
  name: $ns
  labels:
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: security-profiles-operator
  # namespace: openshift-marketplace on OCP
  namespace: olm
spec:
  sourceType: grpc
  image: $CATALOG_IMG
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: security-profiles-operator-sub
  namespace: $ns
spec:
  channel: stable
  name: security-profiles-operator
  source: security-profiles-operator
  sourceNamespace: olm
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: security-profiles-operator
  namespace: $ns
EOF

echo "Installing manifest for custom ns installation.."
cat $manifests

kubectl create -f $manifests
}

function deploy_spo_with_variable() {
    variable=$1
    manifests=examples/olm/$variable-install-resources.yaml

cat << EOF > $manifests
---
apiVersion: v1
kind: Namespace
metadata:
  name: security-profiles-operator
  labels:
    pod-security.kubernetes.io/enforce: privileged
---
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: security-profiles-operator
  namespace: olm
spec:
  sourceType: grpc
  image: $CATALOG_IMG
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: security-profiles-operator-sub
  namespace: security-profiles-operator
spec:
  config:
    env:
    - name: $variable
      value: "true"
  channel: stable
  name: security-profiles-operator
  source: security-profiles-operator
  sourceNamespace: olm
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: security-profiles-operator
  namespace: security-profiles-operator
EOF

    echo "Installing manifest with $variable enabled"
    cat $manifests

    kubectl create -f $manifests
}

function deploy_spo() {
    installation_method=$1
    manifests=examples/olm/$installation_method-install-resources.yaml

    cp examples/olm/install-resources.yaml $manifests

    case $installation_method in
    all)
        ;;
    own)
        echo "spec:
  targetNamespaces:
  - security-profiles-operator" >> $manifests
        ;;
    single)
        echo "spec:
  targetNamespaces:
  - spo-sp-ns" >> $manifests
        ;;
    multi)
        echo "spec:
  targetNamespaces:
  - sp-test-1
  - sp-test-2" >> $manifests
        ;;
    esac

    # let's roll..
    kubectl create -f $manifests
}


function check_spo_is_running() {
    ns=$1

    # Useful in case the CatalogSource is fubar. We retry several times
    # because on transient errors (which are for some reason common even
    # if the catalog is local) the pod gets restarted
    for i in $(seq 1 5); do
        kubectl -nolm wait --for=condition=ready pods -lolm.catalogSource=security-profiles-operator
        install_rv=$?
        if [ $install_rv -ne 0 ]; then
            catalog_logs=$(kubectl -nolm logs $(kubectl -nolm get pods --no-headers -lolm.catalogSource=security-profiles-operator | awk '{print $1}') 2>/dev/null)
            echo $catalog_logs
            kubectl -nolm describe pods -lolm.catalogSource=security-profiles-operator
        else
            break
        fi
    done

    # wait a bit for CSV to appear
    # (jhrozek): I didn't find a useful condition or status to wait for..
    # ..if only there was a way to check if ANY installedCSV is set..
    sleep 30
    CSV=$(kubectl -n$ns get sub security-profiles-operator-sub -ojsonpath='{.status.installedCSV}')
    # wait for the CSV to be actually installed
    kubectl -n$ns wait --for=jsonpath='{.status.phase}'=Succeeded csv $CSV

    # wait for the operator to be ready
    kubectl -n$ns wait --for=condition=ready pod -lname=security-profiles-operator || return 1

    # wait for webhook deploy to be created, kubectl wait for non-existent resource seems to exit with error
    # which is causing random test failure
    # see https://github.com/kubernetes/kubernetes/issues/83242
    for i in $(seq 1 10); do
        found=$(kubectl -n$ns wait --for=condition=ready pod -lname=security-profiles-operator-webhook 2>/dev/null)
        if [[ $found ]]; then
            break
        fi
        sleep 5
    done
    kubectl -n$ns wait --for=condition=ready pod -lname=security-profiles-operator-webhook || return 1

    # wait for spod pod to be created, kubectl wait for non-existent resource seems to exit with error
    # which is causing random test failure
    # see https://github.com/kubernetes/kubernetes/issues/83242
    for i in $(seq 1 10); do
        found=$(kubectl get -n$ns pods -lname=spod 2>/dev/null)
        if [[ $found ]]; then
            break
        fi
        sleep 5
    done
    kubectl -n$ns wait --for=condition=ready pod -lname=spod || return 1

    return 0
}

function assert_spo_csv_installed_in_ns() {
    ns=$1

    [[ $(kubectl get csv -loperators.coreos.com/security-profiles-operator.$ns= -n$ns -oname) ]] || return 1
}

function assert_spo_csv_copied_to() {
    ns=$1
    from=$2

    [[ $(kubectl get csv -lolm.copiedFrom=$from -n$ns -oname) ]] || return 1
}


function smoke_test_all() {
    kubectl create ns sp-test-1
    sp_in_ns sp-test-1
    kubectl wait --for=condition=ready -nsp-test-1 sp log-all || return 1

    kubectl create ns sp-test-2
    sp_in_ns sp-test-2
    kubectl wait --for=condition=ready -nsp-test-2 sp log-all || return 1

    kubectl delete sp --all --all-namespaces
    kubectl delete ns sp-test-{1,2}

    # in this installation method, the CSV is installed into security-profiles-operator
    # and copied into all others
    assert_spo_csv_installed_in_ns security-profiles-operator || return 1
    assert_spo_csv_copied_to default security-profiles-operator || return 1

    return 0
}

function smoke_test_own() {
    sp_in_ns security-profiles-operator
    kubectl wait --for=condition=ready -nsecurity-profiles-operator sp log-all || return 1

    kubectl create ns sp-test-neg
    sp_in_ns sp-test-neg
    kubectl wait --for=condition=ready -nsp-test-neg sp log-all && return 1

    kubectl delete sp --all --all-namespaces
    kubectl delete ns sp-test-neg

    # in this installation method, the CSV is installed into
    # security-profiles-operator ns only
    assert_spo_csv_installed_in_ns security-profiles-operator || return 1
    assert_spo_csv_copied_to default security-profiles-operator && return 1

    return 0
}

function smoke_test_single() {
    kubectl create ns spo-sp-ns
    sp_in_ns spo-sp-ns
    kubectl wait --for=condition=ready -nspo-sp-ns sp log-all || return 1

    kubectl create ns sp-test-neg
    sp_in_ns sp-test-neg
    kubectl wait --for=condition=ready -nsp-test-neg sp log-all && return 1

    # SPO always adds its own ns regardless even if not watched explicitly
    sp_in_ns security-profiles-operator
    kubectl wait --for=condition=ready -nsecurity-profiles-operator sp log-all || return 1

    kubectl delete sp --all --all-namespaces
    kubectl delete ns spo-sp-ns sp-test-neg

    # in this installation method, the CSV is installed into
    # security-profiles-operator ns only
    assert_spo_csv_installed_in_ns security-profiles-operator || return 1
    assert_spo_csv_copied_to default security-profiles-operator && return 1

    return 0
}

function smoke_test_multi() {
    kubectl create ns sp-test-1
    sp_in_ns sp-test-1
    kubectl wait --for=condition=ready -nsp-test-1 sp log-all || return 1

    kubectl create ns sp-test-2
    sp_in_ns sp-test-2
    kubectl wait --for=condition=ready -nsp-test-2 sp log-all || return 1

    # SPO always adds its own ns regardless even if not watched explicitly
    sp_in_ns security-profiles-operator
    kubectl wait --for=condition=ready -nsecurity-profiles-operator sp log-all || return 1

    # negative test, we listen for sp-test-{1,2} only
    kubectl create ns sp-test-3
    sp_in_ns sp-test-3
    kubectl wait --for=condition=ready -nsp-test-3 sp log-all && return 1

    kubectl delete sp --all --all-namespaces
    kubectl delete ns sp-test-{1,2,3}

    # in this installation method, the CSV is installed into
    # security-profiles-operator ns only
    assert_spo_csv_installed_in_ns security-profiles-operator || return 1
    assert_spo_csv_copied_to default security-profiles-operator && return 1

    return 0
}

function smoke_test_custom() {
    kubectl create ns sp-test-1
    sp_in_ns sp-test-1
    kubectl wait --for=condition=ready -nsp-test-1 sp log-all || return 1

    kubectl create ns sp-test-2
    sp_in_ns sp-test-2
    kubectl wait --for=condition=ready -nsp-test-2 sp log-all || return 1

    sp_in_ns spo-lives-here
    kubectl wait --for=condition=ready -nspo-lives-here sp log-all || return 1

    kubectl delete sp --all --all-namespaces
    kubectl delete ns sp-test-1 sp-test-2

    # SPO CSV is installed into the spo-lives-here ns and copied everywhere
    assert_spo_csv_installed_in_ns spo-lives-here || return 1
    assert_spo_csv_copied_to default spo-lives-here || return 1

    return 0
}

function smoke_test() {
    installation_method=$1

    rv=1 # be pessimistic
    smoke_test_$installation_method
    rv=$?
    echo "Smoke test for $installation_method returned $rv"

    return $rv
}

function teardown_spo() {
    installation_method=$1
    manifests=examples/olm/$installation_method-install-resources.yaml

    # profiles might have finalizers
    kubectl delete sp --all --all-namespaces

    kubectl delete -f $manifests
}

function check_spod_property() {
    what=$1

    for i in $(seq 1 5); do
        kubectl -nsecurity-profiles-operator get ds spod -oyaml | grep $what
        found=$?
        if [ $found -ne 0 ]; then
            sleep 3
        else
            break
        fi
    done

    kubectl -nsecurity-profiles-operator get ds spod -oyaml | grep $what || return 1
}

# The actual script begins here
build_and_push_spo
build_and_push_packages

deploy_deps

rv=0
for method in all own single multi; do
    echo "Testing SPO deployment in $method namespace(s)"

    deploy_spo $method || rv=1
    check_spo_is_running security-profiles-operator || rv=1
    smoke_test $method || rv=1

    teardown_spo $method
done

# deployment into the custom namespace is a bit special
echo "Testing SPO deployment in custom namespace(s)"
deploy_spo_in_custom_ns spo-lives-here || rv=1
check_spo_is_running spo-lives-here || rv=1
kubectl get csv -A --show-labels
smoke_test_custom || rv=1

# This is actually part of the next test, but saves us one deployment..
echo "Checking that there's no profilerecording by default"
kubectl -nspo-lives-here get ds spod -oyaml | grep with-recording=false || exit 1

teardown_spo custom

# Test that deploying with ENABLE_BPF/ENABLE_LOG_ENRICHER enables the profilerecorder
echo "Testing SPO deployment with ENABLE_LOG_ENRICHER"
deploy_spo_with_variable ENABLE_LOG_ENRICHER || rv=1
check_spo_is_running security-profiles-operator || rv=1
check_spod_property with-recording=true
teardown_spo ENABLE_LOG_ENRICHER

echo "Testing SPO deployment with ENABLE_BPF_RECORDER"
deploy_spo_with_variable ENABLE_BPF_RECORDER || rv=1
check_spo_is_running security-profiles-operator || rv=1
check_spod_property with-recording=true
teardown_spo ENABLE_BPF_RECORDER

exit $rv
