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

# Installs the last released Helm chart into a kind cluster, upgrades it to the
# chart from this tree and waits until the operator reconciles the spod
# daemonset. `helm lint` cannot catch a chart whose
# RBAC does not cover what the manager actually watches, because the manager
# then waits for its caches forever while still looking healthy, so only an
# install against a real cluster tells the two apart.
#
# UPGRADE_FROM_RELEASE=false installs the chart from this tree directly.
# PREVIOUS_CHART_VERSION selects the released chart, the latest one by default.

set -Eeuo pipefail

# shellcheck source=hack/ci/lib.sh
. "$(dirname "$0")/lib.sh"

NAMESPACE="$SPO_NAMESPACE"
RELEASE=security-profiles-operator
IMAGE_ARCHIVE="${IMAGE_ARCHIVE:-image.tar}"
WAIT_TIMEOUT=300s
UPGRADE_FROM_RELEASE="${UPGRADE_FROM_RELEASE:-true}"
PREVIOUS_CHART="${PREVIOUS_CHART:-oci://registry.k8s.io/security-profiles-operator/charts/security-profiles-operator}"
PREVIOUS_CHART_VERSION="${PREVIOUS_CHART_VERSION:-}"

diagnose() {
  echo "--------------------------------- diagnostics"
  kubectl get securityprofilesoperatordaemons -A -o wide || true
  k get all || true
  # Pods rather than the deployment, because only their events name a failing
  # probe or an image which could not be pulled, and the shared app label so
  # that the spod pods are covered too, not just the manager.
  k describe pods -l app=security-profiles-operator || true
  k logs -l app=security-profiles-operator --all-containers --tail=-1 --prefix || true
  echo "---------------------------------"
}
trap diagnose ERR

echo "Loading $IMAGE_ARCHIVE into the cluster"
kind load image-archive "$IMAGE_ARCHIVE"

install_cert_manager "$WAIT_TIMEOUT"

helm version

wait_for_spod() {
  # Reaching this point already means the manager became ready, which it only
  # does once all of its informer caches synced.
  echo "Waiting for the operator to create the spod daemonset"
  for ((i = 0; i < 60; i++)); do
    if k get daemonset spod &>/dev/null; then
      break
    fi
    sleep 5
  done

  # On the single node kind cluster spod is scheduled exactly once. Asserting
  # that first keeps the checks below from passing on a daemonset with nothing
  # to run, which both `rollout status` and a state of Running would accept.
  kubectl wait --timeout "$WAIT_TIMEOUT" --for jsonpath='{.status.desiredNumberScheduled}'=1 \
    -n "$NAMESPACE" daemonset spod
  k rollout status daemonset spod --timeout "$WAIT_TIMEOUT"
  kubectl wait --timeout "$WAIT_TIMEOUT" --for jsonpath='{.status.state}'=Running \
    -n "$NAMESPACE" securityprofilesoperatordaemon spod
}

# A single replica is enough to exercise the RBAC and leaves CPU for
# cert-manager.
if [[ "$UPGRADE_FROM_RELEASE" == "true" ]]; then
  version_args=()
  if [[ -n "$PREVIOUS_CHART_VERSION" ]]; then
    version_args=(--version "$PREVIOUS_CHART_VERSION")
  fi
  echo "Installing the released Helm chart $PREVIOUS_CHART ${PREVIOUS_CHART_VERSION:-(latest)}"
  helm install "$RELEASE" "$PREVIOUS_CHART" "${version_args[@]}" \
    --namespace "$NAMESPACE" --create-namespace \
    --wait --timeout "$WAIT_TIMEOUT" \
    --set replicaCount=1
  wait_for_spod
  echo "The released Helm chart installs a working operator"

  # Helm never upgrades the CRDs of a chart, see doc/installation.md.
  echo "Updating the CRDs"
  kubectl apply --server-side --force-conflicts -f deploy/helm/crds/crds.yaml
  helm_cmd=(upgrade)
else
  helm_cmd=(install --create-namespace)
fi

# The image archive is built by `podman save`, which keeps the local `localhost`
# prefix, and it is already in the cluster, so it must not be pulled again.
echo "Installing the Helm chart of this tree (helm ${helm_cmd[0]})"
helm "${helm_cmd[@]}" "$RELEASE" deploy/helm \
  --namespace "$NAMESPACE" \
  --wait --timeout "$WAIT_TIMEOUT" \
  --set replicaCount=1 \
  --set spoImage.registry=localhost \
  --set spoImage.repository=security-profiles-operator \
  --set spoImage.tag=latest \
  --set spoImage.pullPolicy=Never

# The upgrade rolls the operator, which then updates the daemonset.
k rollout status deployment security-profiles-operator --timeout "$WAIT_TIMEOUT"
wait_for_spod

# The examples must pass the API server validation and the admission webhooks
# of the installed operator.
echo "Validating the examples against the cluster"
kubectl apply --dry-run=server -f examples/

echo "The Helm chart installs a working operator"
