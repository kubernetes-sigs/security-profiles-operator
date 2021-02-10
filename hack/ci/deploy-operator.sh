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

set -euo pipefail

echo Building the container image
make image

echo Preparing the deployment
sed -i 's;gcr.io/k8s-staging-sp-operator;localhost;g' \
    deploy/operator.yaml deploy/webhook.yaml

sed -i 's;imagePullPolicy: Always;imagePullPolicy: Never;g' \
    deploy/operator.yaml deploy/webhook.yaml

echo Deploying the operator and its dependencies

echo Deploying cert-manager
CERTMGR=https://github.com/jetstack/cert-manager/releases/download/v1.1.0/cert-manager.yaml
kubectl create -f $CERTMGR
kubectl -n cert-manager wait --for condition=ready pod --all

echo Deploying operator
kubectl create -f deploy/operator.yaml

kubectl -n security-profiles-operator wait \
    --for condition=available deployment \
    -l app=security-profiles-operator

kubectl -n security-profiles-operator wait \
    --for condition=ready pod -l app=security-profiles-operator

sleep 5
kubectl -n security-profiles-operator wait \
    --for condition=ready pod -l app=spod

echo Deploying operator webhook
kubectl create -f deploy/webhook.yaml

kubectl -n security-profiles-operator wait \
    --for condition=ready pod --all
