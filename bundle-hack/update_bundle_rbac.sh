# This is a temporary workaround until we get an OCP-specific bundle upstream
# or in case upstream wouldn't allow it
echo "Allowing prometheus-k8s to read metrics"
cat prometheus-k8s.yaml >> ../bundle/manifests/spo-metrics-client_rbac.authorization.k8s.io_v1_clusterrolebinding.yaml
cat spo-metrics-clusterrole-ocp.yaml >> ../bundle/manifests/spo-metrics-client_rbac.authorization.k8s.io_v1_clusterrole.yaml
