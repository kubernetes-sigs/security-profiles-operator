
# This script is used to update the namespace in the bundle manifests to openshift-security-profiles
echo "Replacing default namespace in RBAC manifests"
sed -i "s#namespace: security-profiles-operator#namespace: openshift-security-profiles#g" ../bundle/manifests/spo-metrics-client_rbac.authorization.k8s.io_v1_clusterrolebinding.yaml
sed -i "s#namespace: security-profiles-operator#namespace: openshift-security-profiles#g" ../bundle/manifests/spo-webhook_rbac.authorization.k8s.io_v1_clusterrolebinding.yaml
sed -i "s#namespace: security-profiles-operator#namespace: openshift-security-profiles#g" ../bundle/manifests/spod_rbac.authorization.k8s.io_v1_clusterrolebinding.yaml
sed -i "s#namespace: security-profiles-operator#namespace: openshift-security-profiles#g" ../bundle/manifests/spod_rbac.authorization.k8s.io_v1_rolebinding.yaml

