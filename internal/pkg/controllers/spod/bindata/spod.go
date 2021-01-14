/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bindata

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// NOTE(jaosorior): We should switch this for a proper bindata solution.
// nolint: lll
const spodManifest = `---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: security-profiles-operator
  namespace: security-profiles-operator
spec:
  selector:
    matchLabels:
      app: spod
  template:
    metadata:
      annotations:
        openshift.io/scc: privileged
        seccomp.security.alpha.kubernetes.io/pod: runtime/default
        container.seccomp.security.alpha.kubernetes.io/security-profiles-operator: localhost/security-profiles-operator.json
      labels:
        app: spod
    spec:
      serviceAccountName: security-profiles-operator
      initContainers:
        - name: non-root-enabler
          image: bash
          # Creates folder /var/lib/security-profiles-operator, sets 2000:2000 as its
          # owner and symlink it to /var/lib/kubelet/seccomp/operator. This is
          # required to allow the main container to run as non-root.
          command: [bash, -c]
          args:
            - |+
              set -euo pipefail

              if [ ! -d $KUBELET_SECCOMP_ROOT ]; then
                /bin/mkdir -m 0744 -p $KUBELET_SECCOMP_ROOT
              fi

              /bin/mkdir -p $OPERATOR_ROOT
              /bin/chmod 0744 $OPERATOR_ROOT

              if [ ! -L $OPERATOR_SYMLINK ]; then
                /bin/ln -s $OPERATOR_ROOT $OPERATOR_SYMLINK
              fi

              /bin/chown -R 2000:2000 $OPERATOR_ROOT
              cp -f -v /opt/seccomp-profiles/* $KUBELET_SECCOMP_ROOT
          env:
            - name: KUBELET_SECCOMP_ROOT
              value: /var/lib/kubelet/seccomp
            - name: OPERATOR_SYMLINK
              value: $(KUBELET_SECCOMP_ROOT)/operator
            - name: OPERATOR_ROOT
              value: /var/lib/security-profiles-operator
          volumeMounts:
            - name: host-varlib-volume
              mountPath: /var/lib
            - name: profile-configmap-volume
              mountPath: /opt/seccomp-profiles
              readOnly: true
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
              add: ["CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE"]
            runAsUser: 0
            seLinuxOptions:
              # FIXME(jaosorior): Use a more restricted selinux type
              type: spc_t
          resources:
            requests:
              memory: "32Mi"
              cpu: "100m"
              ephemeral-storage: "10Mi"
            limits:
              memory: "64Mi"
              cpu: "250m"
              ephemeral-storage: "50Mi"
      containers:
        - name: security-profiles-operator
          image: security-profiles-operator
          args:
          - daemon
          imagePullPolicy: Always
          volumeMounts:
          - name: host-operator-volume
            mountPath: /var/lib/kubelet/seccomp/operator
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsUser: 2000
            runAsGroup: 2000
            capabilities:
              drop: ["ALL"]
            seLinuxOptions:
              # FIXME(jaosorior): Use a more restricted selinux type
              type: spc_t
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
              ephemeral-storage: "50Mi"
            limits:
              memory: "128Mi"
              cpu: "300m"
              ephemeral-storage: "200Mi"
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
      volumes:
      # /var/lib is used as symlinks cannot be created across different volumes
      - name: host-varlib-volume
        hostPath:
          path: /var/lib
          type: Directory
      - name: host-operator-volume
        hostPath:
          path: /var/lib/security-profiles-operator
          type: DirectoryOrCreate
      - name: profile-configmap-volume
        configMap:
          name: security-profiles-operator-profile
      tolerations:
        - effect: NoSchedule
          key: node-role.kubernetes.io/master
        - effect: NoSchedule
          key: node-role.kubernetes.io/control-plane
        - effect: NoExecute
          key: node.kubernetes.io/not-ready
          operator: Exists
      nodeSelector:
        kubernetes.io/os: linux
`

func GetReferenceSPOd() (*appsv1.DaemonSet, error) {
	rawDS, err := rawObjectToUnstructured(spodManifest)
	if err != nil {
		return nil, fmt.Errorf("error parsing DS manifest: %w", err)
	}
	spod := &appsv1.DaemonSet{}
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(rawDS.Object, spod)
	if err != nil {
		return nil, fmt.Errorf("error converting unstructured DS to implementation object: %w", err)
	}
	return spod, nil
}
