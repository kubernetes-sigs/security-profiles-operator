# security-profiles-operator

![Version: 0.6.1-dev](https://img.shields.io/badge/Version-0.6.1--dev-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.6.1-dev](https://img.shields.io/badge/AppVersion-0.6.1--dev-informational?style=flat-square)

The Kubernetes Security Profiles Operator.

## Installation

please refer to [Installation Guide](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md#installation-using-helm)

## Values

| Key                                         | Type | Default | Description                                    |
|---------------------------------------------|------|---------|------------------------------------------------|
| affinity                                    | object | `{}` | `pod affinity rules`                           |
| autoscaling.enabled                         | bool | `false` | `enable autoscaling or not`                    |
| daemon.affinity                             | object | `{}` | `daemonset affinity rules`                     |
| daemon.resources.limits.cpu                 | string | unlimited | `cpu limits for the daemonset`                 |
| daemon.resources.limits.ephemeral-storage   | string | `"200Mi"` | `storage limits for the daemonset`             |
| daemon.resources.limits.memory              | string | `"128Mi"` | `memory limits for the daemonset`              |
| daemon.resources.requests.cpu               | string | `"100m"` | `cpu requests for the daemonset`               |
| daemon.resources.requests.ephemeral-storage | string | `"50Mi"` | `storage requests for the daemonset`           |
| daemon.resources.requests.memory            | string | `"64Mi"` | `memory requests for the daemonset`            |
| daemon.tolerations                          | list | `[]` | `a list of daemonset tolerations rules`        |
| enableAppArmor                              | bool | `false` | `enable apparmor or not`                       |
| enableBpfRecorder                           | bool | `false` | `enable BpfRecorder or not`                    |
| enableLogEnricher                           | bool | `false` | `enable log enricher or not`                   |
| enableJsonEnricher                          | bool | `false` | `enable audit JSON enricher or not`            |
| enableProfiling                             | bool | `false` | `enable profiling or not`                      |
| enableSelinux                               | bool | `false` | `enable selinux or not`                        |
| nameOverride                                | string | `""` | `used for generating labels`                   |
| nodeSelector                                | object | `{}` | `specify on which node to deploy the workload` |
| podSecurityContext                          | object | `` | `pod security contexts`                        |
| replicaCount                                | int | `3` | `the number of replicas of the pods`           |
| resources.limits.memory                     | string | `"128Mi"` | `memory limits for the pod`                    |
| resources.requests.cpu                      | string | `"250m"` | `cpu requests for the pod`                     |
| resources.requests.memory                   | string | `"50Mi"` | `memory requests for pod`                      |
| spoImage.registry                           | string | `"gcr.io"` | `the registry for the spoImage`                |
| spoImage.repository                         | string | `"k8s-staging-sp-operator/security-profiles-operator"` | `the repository for the spoImage`              |
| spoImage.tag                                | string | `"latest"` | `tag for spoImage`                             |
| tolerations                                 | list | `[]` | `a list of pod tolerations rules`              |
| verbosity                                   | int | `0` | `the log level for the spo`                    |
