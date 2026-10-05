# security-profiles-operator

![Version: 1.1.1](https://img.shields.io/badge/Version-1.1.1-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.1.1](https://img.shields.io/badge/AppVersion-1.1.1-informational?style=flat-square)

The Kubernetes Security Profiles Operator.

## Installation

please refer to [Installation Guide](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/doc/installation.md#installation-using-helm)

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | pod affinity rules |
| autoscaling.enabled | bool | `false` | do not set the replica count of the operator deployment, for example when it is scaled externally |
| daemon.affinity | object | `{}` | daemonset affinity rules |
| daemon.resources.limits.cpu | string | unlimited | cpu limits for the daemonset |
| daemon.resources.limits.ephemeral-storage | string | `"200Mi"` | storage limits for the daemonset |
| daemon.resources.limits.memory | string | `"128Mi"` | memory limits for the daemonset |
| daemon.resources.requests.cpu | string | `"100m"` | cpu requests for the daemonset |
| daemon.resources.requests.ephemeral-storage | string | `"50Mi"` | storage requests for the daemonset |
| daemon.resources.requests.memory | string | `"64Mi"` | memory requests for the daemonset |
| daemon.tolerations | list | `NoSchedule` on `node-role.kubernetes.io/master` and `node-role.kubernetes.io/control-plane`, `NoExecute` on `node.kubernetes.io/not-ready` | a list of daemonset tolerations rules |
| enableAppArmor | bool | `false` | enable apparmor or not |
| enableBpfRecorder | bool | `false` | enable BpfRecorder or not |
| enableLogEnricher | bool | `false` | enable log enricher or not |
| enableJsonEnricher | bool | `false` | enable audit JSON enricher or not |
| enableProfiling | bool | `false` | enable profiling or not |
| enableSelinux | bool | `false` | deprecated, use `selinux.enable` instead |
| fullnameOverride | string | `""` | override the generated full name |
| kubeletDir | string | `"/var/lib/kubelet"` | the kubelet root directory of the nodes, where the seccomp profiles get installed |
| nameOverride | string | `""` | used for generating labels |
| nodeSelector | object | `{}` | specify on which node to deploy the workload |
| podDisruptionBudget.enabled | bool | `true` | create a PodDisruptionBudget for the operator deployment |
| podDisruptionBudget.minAvailable | int or string | `1` | the operator replicas to keep during voluntary disruptions like node drains; with a single replica, `1` blocks the drain of its node |
| podSecurityContext | object | `{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}` | pod security contexts |
| replicaCount | int | `3` | the number of replicas of the pods |
| restrictToNamespace | string | `""` | restrict the operator to a single namespace |
| resources.limits.cpu | string | `"500m"` | cpu limits for the pod |
| resources.limits.memory | string | `"128Mi"` | memory limits for the pod |
| resources.requests.cpu | string | `"250m"` | cpu requests for the pod |
| resources.requests.memory | string | `"50Mi"` | memory requests for pod |
| selinux.customTemplatesConfigMap | string | `""` | ConfigMap with .cil files replacing the bundled selinuxd templates |
| selinux.enable | bool | unset | enable selinux or not, overrides `enableSelinux` |
| selinux.enableRawSelinuxProfiles | bool | `true` | enable RawSelinuxProfile support or not |
| selinux.options | object | `{}` | SELinux policy restrictions, see `spec.selinux.options` of the SPOD |
| selinux.typeTag | string | `"spc_t"` | the SELinux type of the daemon pod |
| selinuxdImage.{default,el8,el9,fedora}.registry | string | `"quay.io"` | the registry for the selinuxd images |
| selinuxdImage.{default,el8,el9,fedora}.repository | string | `"security-profiles-operator/selinuxd"`, `"security-profiles-operator/selinuxd-el8"`, ... | the repository for the selinuxd images |
| selinuxdImage.{default,el8,el9,fedora}.tag | string | `"latest"` | tag for the selinuxd images, only used when the digest is empty |
| selinuxdImage.{default,el8,el9,fedora}.digest | string | the digest of the current `latest` tag | digest of the selinuxd images, set to `""` to use the tag |
| spoImage.pullPolicy | string | `"IfNotPresent"` | pull policy for spoImage |
| spoImage.registry | string | `"registry.k8s.io"` | the registry for the spoImage |
| spoImage.repository | string | `"security-profiles-operator/security-profiles-operator"` | the repository for the spoImage |
| spoImage.tag | string | `"v1.1.1"` | tag for spoImage |
| tolerations | list | `[]` | a list of pod tolerations rules |
| topologySpreadConstraints | list | `ScheduleAnyway` spread with `maxSkew: 1` across `kubernetes.io/hostname` and `topology.kubernetes.io/zone` | topology spread constraints of the operator pods; constraints without `labelSelector` get the selector labels of the operator pods |
| verbosity | int | `0` | the log level for the spo |
| webhook.tolerations | list | `[]` | webhook tolerations (inherits daemon tolerations when empty) |
