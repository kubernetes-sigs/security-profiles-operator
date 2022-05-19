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

AUDIT_LOG=/tmp/kube-apiserver-audit.log
NAMESPACE=security-profiles-operator
declare -a SERVICE_ACCOUNTS=(security-profiles-operator spod spo-webhook)

for SA in "${SERVICE_ACCOUNTS[@]}"; do
    echo "Generating RBAC for serviceaccount $SA"
    audit2rbac -f $AUDIT_LOG --serviceaccount "$NAMESPACE:$SA"
done
