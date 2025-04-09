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

set -euox pipefail

OLM_VERSION=v0.30.0

REPO=localhost:5000
IMG=${REPO}/security-profiles-operator:${GITHUB_SHA}
BUNDLE_IMG=${REPO}/security-profiles-operator-bundle:v${GITHUB_SHA}
CATALOG_IMG=${REPO}/security-profiles-operator-catalog:v${GITHUB_SHA}

function create_sp() {
  kubectl create -f - <<EOF
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log-all
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
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.1/cert-manager.yaml
  kubectl_wait -ncert-manager --for condition=ready pod -l app.kubernetes.io/instance=cert-manager

  # All installation methods run off the same catalog
  sed -i "s#gcr.io/k8s-staging-sp-operator/security-profiles-operator-catalog:latest#${CATALOG_IMG}#g" examples/olm/install-resources.yaml

}

function deploy_spo_in_custom_ns() {
  ns=$1
  manifests=examples/olm/custom-install-resources.yaml

  cat <<EOF >$manifests
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

  cat <<EOF >$manifests
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
  all) ;;
  own)
    echo "spec:
  targetNamespaces:
  - security-profiles-operator" >>$manifests
    ;;
  single)
    echo "spec:
  targetNamespaces:
  - spo-sp-ns" >>$manifests
    ;;
  multi)
    echo "spec:
  targetNamespaces:
  - sp-test-1
  - sp-test-2" >>$manifests
    ;;
  esac

  # let's roll..
  kubectl create -f $manifests
}

function try_until_ok() {
  { set +x; } 2>/dev/null # disable trace output temporarily

  local cmd="$1"
  shift # Remove the command from the argument list

  # retry until it succeeds or until time is up
  local end_time=$(($(date +%s) + 180))
  while (($(date +%s) < end_time)); do
    local cmd_start_time=$(date +%s)
    if "$cmd" "$@" 1>/dev/null 2>/dev/null; then
      break
    fi
    if (($(date +%s) == $cmd_start_time)); then
      sleep 1
    fi
  done

  set -x
  # run one final time with all output enabled
  "$cmd" "$@"
}

function kubectl_wait() {
  # kubectl wait for non-existent resource seems to exit with error, which is causing random test failures.
  # see https://github.com/kubernetes/kubernetes/issues/83242
  try_until_ok kubectl wait --timeout 1s "$@"
}

function check_spo_is_running() {
  ns=$1

  # Useful in case the CatalogSource is fubar. We retry several times
  # because on transient errors (which are for some reason common even
  # if the catalog is local) the pod gets restarted
  for i in $(seq 1 5); do
    kubectl_wait -nolm --for=condition=ready pods -lolm.catalogSource=security-profiles-operator
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
  CSV=$(try_until_ok kubectl -n$ns get sub security-profiles-operator-sub -ojsonpath='{.status.installedCSV}')

  # wait for the CSV to be actually installed
  kubectl_wait -n$ns --for=jsonpath='{.status.phase}'=Succeeded csv $CSV

  # wait for the operator to be ready
  kubectl_wait -n$ns --for=condition=ready pod -lname=security-profiles-operator || return 1

  # wait for webhook deploy to be created
  kubectl_wait -n$ns --for=condition=ready pod -lname=security-profiles-operator-webhook || return 1

  # wait for spod pod to be created
  kubectl_wait -n$ns --for=condition=ready pod -lname=spod || return 1

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
  create_sp
  kubectl_wait --for=condition=ready sp log-all || return 1

  kubectl delete sp --all

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
  kubectl delete sp --all

  kubectl delete -f $manifests
}

function check_spod_property() {
  what=$1
  try_until_ok kubectl -nsecurity-profiles-operator get ds spod -oyaml | grep $what
}

# The actual script begins here
build_and_push_spo
build_and_push_packages

deploy_deps

rv=0
for method in all; do
  echo "Testing SPO deployment in $method namespace(s)"

  deploy_spo $method || rv=1
  check_spo_is_running security-profiles-operator || rv=1
  smoke_test $method || rv=1

  teardown_spo $method

  if [ $rv -gt 0 ]; then
    echo "SPO deployment in $method namespace(s) failed"
    exit $rv
  fi
done

# deployment into the custom namespace is a bit special
echo "Testing SPO deployment in custom namespace(s)"
deploy_spo_in_custom_ns spo-lives-here || exit 1
check_spo_is_running spo-lives-here || exit 1
kubectl get csv -A --show-labels
smoke_test_all || exit 1

# This is actually part of the next test, but saves us one deployment..
echo "Checking that there's no profilerecording by default"
kubectl -nspo-lives-here get ds spod -oyaml | grep with-recording=false || exit 1

teardown_spo custom

# Test that deploying with ENABLE_BPF/ENABLE_LOG_ENRICHER enables the profilerecorder
echo "Testing SPO deployment with ENABLE_LOG_ENRICHER"
deploy_spo_with_variable ENABLE_LOG_ENRICHER || exit 1
check_spo_is_running security-profiles-operator || exit 1
check_spod_property with-recording=true || exit 1
teardown_spo ENABLE_LOG_ENRICHER

echo "Testing SPO deployment with ENABLE_BPF_RECORDER"
deploy_spo_with_variable ENABLE_BPF_RECORDER || exit 1
check_spo_is_running security-profiles-operator || exit 1
check_spod_property with-recording=true || exit 1
teardown_spo ENABLE_BPF_RECORDER

exit 0
