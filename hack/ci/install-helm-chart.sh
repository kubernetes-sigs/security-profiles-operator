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

# Installs the Helm chart from this tree into a kind cluster and waits until the
# operator reconciles the spod daemonset. `helm lint` cannot catch a chart whose
# RBAC does not cover what the manager actually watches, because the manager
# then waits for its caches forever while still looking healthy, so only an
# install against a real cluster tells the two apart.

set -Eeuo pipefail

NAMESPACE=security-profiles-operator
CERT_MANAGER_VERSION=v1.21.1
IMAGE_ARCHIVE="${IMAGE_ARCHIVE:-image.tar}"
WAIT_TIMEOUT=300s

k() {
  kubectl -n "$NAMESPACE" "$@"
}

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

echo "Installing cert-manager $CERT_MANAGER_VERSION"
kubectl apply -f \
  "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml"
kubectl wait --timeout "$WAIT_TIMEOUT" --for condition=Available \
  -n cert-manager deployment --all

# The image archive is built by `podman save`, which keeps the local `localhost`
# prefix, and it is already in the cluster, so it must not be pulled again. A
# single replica is enough to exercise the RBAC and leaves CPU for cert-manager.
echo "Installing the Helm chart"
helm install security-profiles-operator deploy/helm \
  --namespace "$NAMESPACE" --create-namespace \
  --wait --timeout "$WAIT_TIMEOUT" \
  --set replicaCount=1 \
  --set spoImage.registry=localhost \
  --set spoImage.repository=security-profiles-operator \
  --set spoImage.tag=latest \
  --set spoImage.pullPolicy=Never

# Reaching this point already means the manager became ready, which it only does
# once all of its informer caches synced.
echo "Waiting for the operator to create the spod daemonset"
for ((i = 0; i < 60; i++)); do
  if k get daemonset spod &>/dev/null; then
    break
  fi
  sleep 5
done

# On the single node kind cluster spod is scheduled exactly once. Asserting that
# first keeps the checks below from passing on a daemonset with nothing to run,
# which both `rollout status` and a state of Running would accept.
kubectl wait --timeout "$WAIT_TIMEOUT" --for jsonpath='{.status.desiredNumberScheduled}'=1 \
  -n "$NAMESPACE" daemonset spod
k rollout status daemonset spod --timeout "$WAIT_TIMEOUT"
kubectl wait --timeout "$WAIT_TIMEOUT" --for jsonpath='{.status.state}'=Running \
  -n "$NAMESPACE" securityprofilesoperatordaemon spod

echo "The Helm chart installs a working operator"
