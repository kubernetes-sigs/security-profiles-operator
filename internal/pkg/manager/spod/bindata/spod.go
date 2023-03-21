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
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	userRoot                  int64
	falsely                         = false
	truly                           = true
	userRootless                    = int64(config.UserRootless)
	hostPathDirectory               = corev1.HostPathDirectory
	hostPathDirectoryOrCreate       = corev1.HostPathDirectoryOrCreate
	hostPathFile                    = corev1.HostPathFile
	servicePort               int32 = 443
	healthzPath                     = "/healthz"
	etcOSReleasePath                = "/etc/os-release"
	metricsPort               int32 = 9443
	metricsCertPath                 = "/var/run/secrets/metrics"
	metricsServerCert               = "metrics-server-cert"
	openshiftCertAnnotation         = "service.beta.openshift.io/serving-cert-secret-name"
	localSeccompProfilePath         = LocalSeccompProfilePath
)

const (
	HomeDirectory                              = "/home"
	TempDirectory                              = "/tmp"
	SelinuxDropDirectory                       = "/etc/selinux.d"
	SelinuxdPrivateDir                         = "/var/run/selinuxd"
	SelinuxdSocketPath                         = SelinuxdPrivateDir + "/selinuxd.sock"
	SelinuxdDBPath                             = SelinuxdPrivateDir + "/selinuxd.db"
	MetricsImage                               = "gcr.io/kubebuilder/kube-rbac-proxy:v0.13.1"
	sysKernelDebugPath                         = "/sys/kernel/debug"
	InitContainerIDNonRootenabler              = 0
	InitContainerIDSelinuxSharedPoliciesCopier = 1
	ContainerIDDaemon                          = 0
	ContainerIDSelinuxd                        = 1
	ContainerIDLogEnricher                     = 2
	ContainerIDBpfRecorder                     = 3
	ContainerIDMetrics                         = 4
	DefaultHostProcPath                        = "/proc"
	MetricsContainerName                       = "metrics"
	SelinuxContainerName                       = "selinuxd"
	LogEnricherContainerName                   = "log-enricher"
	BpfRecorderContainerName                   = "bpf-recorder"
	NonRootEnablerContainerName                = "non-root-enabler"
	SelinuxPoliciesCopierContainerName         = "selinux-shared-policies-copier"
	LocalSeccompProfilePath                    = "security-profiles-operator.json"
	DefaultPriorityClassName                   = "system-node-critical"
)

var DefaultSPOD = &spodv1alpha1.SecurityProfilesOperatorDaemon{
	ObjectMeta: metav1.ObjectMeta{
		Name:   config.SPOdName,
		Labels: map[string]string{"app": config.OperatorName},
	},
	Spec: spodv1alpha1.SPODSpec{
		Verbosity:           0,
		EnableProfiling:     false,
		EnableSelinux:       nil,
		EnableLogEnricher:   false,
		EnableBpfRecorder:   false,
		StaticWebhookConfig: false,
		HostProcVolumePath:  DefaultHostProcPath,
		PriorityClassName:   DefaultPriorityClassName,
		SelinuxOpts: spodv1alpha1.SelinuxOptions{
			AllowedSystemProfiles: []string{
				"container",
			},
		},
		Tolerations: []corev1.Toleration{
			{
				Key:      "node-role.kubernetes.io/master",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			},
			{
				Key:      "node-role.kubernetes.io/control-plane",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoSchedule,
			},
			{
				Key:      "node.kubernetes.io/not-ready",
				Operator: corev1.TolerationOpExists,
				Effect:   corev1.TaintEffectNoExecute,
			},
		},
	},
}

var Manifest = &appsv1.DaemonSet{
	ObjectMeta: metav1.ObjectMeta{
		Name:      config.OperatorName,
		Namespace: config.OperatorName,
	},
	Spec: appsv1.DaemonSetSpec{
		UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
			Type: appsv1.RollingUpdateDaemonSetStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDaemonSet{
				// Update everything in parallel
				MaxUnavailable: &intstr.IntOrString{Type: intstr.String, StrVal: "100%"},
			},
		},
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app":  config.OperatorName,
				"name": config.SPOdName,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"openshift.io/scc": "privileged",
				},
				Labels: map[string]string{
					"app":  config.OperatorName,
					"name": config.SPOdName,
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: config.SPOdServiceAccount,
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
				InitContainers: []corev1.Container{
					{
						Name:            NonRootEnablerContainerName,
						Args:            []string{"non-root-enabler"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host-varlib-volume",
								MountPath: "/var/lib",
							},
							{
								Name:      "operator-profiles-volume",
								MountPath: "/opt/spo-profiles",
								ReadOnly:  true,
							},
							{
								Name:      "host-root-volume",
								MountPath: config.HostRoot,
							},
							{
								Name:      "metrics-cert-volume",
								MountPath: metricsCertPath,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
								Add:  []corev1.Capability{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE"},
							},
							RunAsUser: &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: "spc_t",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("32Mi"),
								corev1.ResourceCPU:              resource.MustParse("100m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("64Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: config.NodeNameEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
						},
					},
					{
						Name:  SelinuxPoliciesCopierContainerName,
						Image: "quay.io/security-profiles-operator/selinuxd",
						// Primes the volume mount under /etc/selinux.d with the
						// shared policies shipped by selinuxd and makes sure the volume mount
						// is writable by 65535 in order for the controller to be able to
						// write the policy files. In the future, the policy files should
						// be shipped by selinuxd directly.
						//
						// The directory is writable by 65535 (the operator writes to this dir) and
						// readable by root (selinuxd reads the policies and runs as root).
						// Explicitly allowing root makes sure no dac_override audit messages
						// are logged even in absence of CAP_DAC_OVERRIDE.
						//
						// If, in the future we wanted to make the DS more compact, we could move
						// the chown+chmod to the previous init container and move the copying of
						// the files into a lifecycle handler of selinuxd.
						Command: []string{"bash", "-c"},
						Args: []string{
							`set -x
chown 65535:0 /etc/selinux.d
chmod 750 /etc/selinux.d
semodule -i /usr/share/selinuxd/templates/*.cil
semodule -i /opt/spo-profiles/selinuxd.cil
semodule -i /opt/spo-profiles/selinuxrecording.cil
`,
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "selinux-drop-dir",
								MountPath: SelinuxDropDirectory,
							},
							{
								Name:      "operator-profiles-volume",
								MountPath: "/opt/spo-profiles",
								ReadOnly:  true,
							},
							{
								Name:      "host-fsselinux-volume",
								MountPath: "/sys/fs/selinux",
							},
							{
								Name:      "host-etcselinux-volume",
								MountPath: "/etc/selinux",
							},
							{
								Name:      "host-varlibselinux-volume",
								MountPath: "/var/lib/selinux",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
								Add:  []corev1.Capability{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE"},
							},
							RunAsUser: &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: "spc_t",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("32Mi"),
								corev1.ResourceCPU:              resource.MustParse("100m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
							},
							Limits: corev1.ResourceList{
								// libsemanage is very resource hungry...
								corev1.ResourceMemory:           resource.MustParse("1024Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:            config.OperatorName,
						Args:            []string{"daemon"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host-operator-volume",
								MountPath: config.ProfilesRootPath(),
							},
							{
								Name:      "selinux-drop-dir",
								MountPath: SelinuxDropDirectory,
							},
							{
								Name:      "selinuxd-private-volume",
								MountPath: SelinuxdPrivateDir,
							},
							{
								Name:      "profile-recording-output-volume",
								MountPath: config.ProfileRecordingOutputPath,
							},
							{
								Name:      "grpc-server-volume",
								MountPath: filepath.Dir(config.GRPCServerSocketMetrics),
							},
							{
								Name:      "home-volume",
								MountPath: HomeDirectory,
							},
							{
								Name:      "tmp-volume",
								MountPath: TempDirectory,
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{"ALL"},
							},
							RunAsUser:  &userRootless,
							RunAsGroup: &userRootless,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: "spc_t",
							},
							SeccompProfile: &corev1.SeccompProfile{
								Type:             corev1.SeccompProfileTypeLocalhost,
								LocalhostProfile: &localSeccompProfilePath,
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("64Mi"),
								corev1.ResourceCPU:              resource.MustParse("100m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("128Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("200Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: config.NodeNameEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name: "OPERATOR_NAMESPACE",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.namespace",
									},
								},
							},
							{
								// Note that this will be set per SPOD instance
								Name:  config.SPOdNameEnvKey,
								Value: config.SPOdName,
							},
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
							{
								Name:  "HOME",
								Value: HomeDirectory,
							},
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "liveness-port",
								ContainerPort: config.HealthProbePort,
								Protocol:      corev1.ProtocolTCP,
							},
						},
						StartupProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path:   healthzPath,
								Port:   intstr.FromString("liveness-port"),
								Scheme: corev1.URISchemeHTTP,
							}},
							FailureThreshold: 10, //nolint:gomnd // test number
							PeriodSeconds:    3,  //nolint:gomnd // test number
							TimeoutSeconds:   1,
							SuccessThreshold: 1,
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path:   healthzPath,
								Port:   intstr.FromString("liveness-port"),
								Scheme: corev1.URISchemeHTTP,
							}},
							FailureThreshold: 1,
							PeriodSeconds:    10, //nolint:gomnd // test number
							TimeoutSeconds:   1,
							SuccessThreshold: 1,
						},
					},
					{
						Name:  SelinuxContainerName,
						Image: "quay.io/security-profiles-operator/selinuxd",
						Args: []string{
							"daemon",
							"--datastore-path", SelinuxdDBPath,
							"--socket-path", SelinuxdSocketPath,
							"--socket-uid", "0",
							"--socket-gid", "65535",
						},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "selinux-drop-dir",
								MountPath: SelinuxDropDirectory,
								ReadOnly:  true,
							},
							{
								Name:      "selinuxd-private-volume",
								MountPath: SelinuxdPrivateDir,
							},
							{
								Name:      "host-fsselinux-volume",
								MountPath: "/sys/fs/selinux",
							},
							{
								Name:      "host-etcselinux-volume",
								MountPath: "/etc/selinux",
							},
							{
								Name:      "host-varlibselinux-volume",
								MountPath: "/var/lib/selinux",
							},
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							RunAsUser:              &userRoot,
							RunAsGroup:             &userRoot,
							Capabilities: &corev1.Capabilities{
								Add: []corev1.Capability{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE"},
							},
							SELinuxOptions: &corev1.SELinuxOptions{
								Type: "selinuxd.process",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("512Mi"),
								corev1.ResourceCPU:              resource.MustParse("100m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("200Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("1024Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("400Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
						},
					},
					{
						Name:            LogEnricherContainerName,
						Args:            []string{"log-enricher"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host-auditlog-volume",
								MountPath: filepath.Dir(config.AuditLogPath),
								ReadOnly:  true,
							},
							{
								Name:      "host-syslog-volume",
								MountPath: filepath.Dir(config.SyslogLogPath),
								ReadOnly:  true,
							},
							{
								Name:      "grpc-server-volume",
								MountPath: filepath.Dir(config.GRPCServerSocketEnricher),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							Privileged:             &truly,
							RunAsUser:              &userRoot,
							RunAsGroup:             &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(pjbgf): Use a more restricted selinux type
								Type: "spc_t",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("64Mi"),
								corev1.ResourceCPU:              resource.MustParse("50m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("256Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("128Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: config.NodeNameEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
						},
					},
					{
						Name:            BpfRecorderContainerName,
						Args:            []string{"bpf-recorder"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "sys-kernel-debug-volume",
								MountPath: sysKernelDebugPath,
								ReadOnly:  true,
							},
							{
								Name:      "host-etc-osrelease-volume",
								MountPath: etcOSReleasePath,
							},
							{
								Name:      "tmp-volume",
								MountPath: TempDirectory,
							},
							{
								Name:      "grpc-server-volume",
								MountPath: filepath.Dir(config.GRPCServerSocketBpfRecorder),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							Privileged:             &truly,
							RunAsUser:              &userRoot,
							RunAsGroup:             &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(pjbgf): Use a more restricted selinux type
								Type: "spc_t",
							},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("64Mi"),
								corev1.ResourceCPU:              resource.MustParse("50m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("128Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("20Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{
								Name: config.NodeNameEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							{
								Name:  config.KubeletDirEnvKey,
								Value: config.KubeletDir(),
							},
						},
					},
					{
						Name:            MetricsContainerName,
						Image:           MetricsImage,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							fmt.Sprintf("--secure-listen-address=0.0.0.0:%d", metricsPort),
							"--upstream=http://127.0.0.1:8080",
							"--v=10",
							fmt.Sprintf("--tls-cert-file=%s", filepath.Join(metricsCertPath, "tls.crt")),
							fmt.Sprintf("--tls-private-key-file=%s", filepath.Join(metricsCertPath, "tls.key")),
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("32Mi"),
								corev1.ResourceCPU:              resource.MustParse("50m"),
								corev1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceMemory:           resource.MustParse("128Mi"),
								corev1.ResourceEphemeralStorage: resource.MustParse("20Mi"),
							},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
						},
						Ports: []corev1.ContainerPort{
							{Name: "https", ContainerPort: metricsPort},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "metrics-cert-volume",
								MountPath: metricsCertPath,
								ReadOnly:  true,
							},
						},
					},
				},
				Volumes: []corev1.Volume{
					// /var/lib is used as symlinks cannot be created across
					// different volumes
					{
						Name: "host-varlib-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "host-operator-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/security-profiles-operator",
								Type: &hostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "operator-profiles-volume",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "security-profiles-operator-profile",
								},
							},
						},
					},
					{
						Name: "selinux-drop-dir",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "selinuxd-private-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					// The following host mounts only make sense on a SELinux enabled
					// system. But if SELinux is not configured, then they wouldn't be
					// used by any container, so it's OK to define them unconditionally
					{
						Name: "host-fsselinux-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/sys/fs/selinux",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "host-etcselinux-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/etc/selinux",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "host-varlibselinux-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/var/lib/selinux",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "profile-recording-output-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: config.ProfileRecordingOutputPath,
								Type: &hostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "host-auditlog-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: filepath.Dir(config.AuditLogPath),
								Type: &hostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "host-syslog-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: filepath.Dir(config.SyslogLogPath),
								Type: &hostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "metrics-cert-volume",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: metricsServerCert,
							},
						},
					},
					{
						Name: "sys-kernel-debug-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: sysKernelDebugPath,
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "host-etc-osrelease-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: etcOSReleasePath,
								Type: &hostPathFile,
							},
						},
					},
					{
						Name: "tmp-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "grpc-server-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					{
						Name: "host-root-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "home-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
				},
				Tolerations: []corev1.Toleration{
					{
						Effect: corev1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/master",
					},
					{
						Effect: corev1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/control-plane",
					},
					{
						Effect:   corev1.TaintEffectNoExecute,
						Key:      "node.kubernetes.io/not-ready",
						Operator: corev1.TolerationOpExists,
					},
				},
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
	},
}

func GetMetricsService(
	namespace string,
	caInjectType CAInjectType,
) *corev1.Service {
	service := metricsService.DeepCopy()
	service.Namespace = namespace

	if caInjectType == CAInjectTypeOpenShift {
		service.Annotations = map[string]string{
			openshiftCertAnnotation: metricsServerCert,
		}
	}

	return service
}

var metricsService = &corev1.Service{
	ObjectMeta: metav1.ObjectMeta{
		Name: "metrics",
		Labels: map[string]string{
			"app":  config.OperatorName,
			"name": config.SPOdName,
		},
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:       "https",
				Port:       servicePort,
				TargetPort: intstr.FromInt(int(metricsPort)),
			},
		},
		Selector: map[string]string{
			"app":  config.OperatorName,
			"name": config.SPOdName,
		},
	},
}

// CustomHostProcVolume returns a new host /proc path volume as well as
// corresponding mount used for the log-enricher or bpf-recorder.
func CustomHostProcVolume(path string) (corev1.Volume, corev1.VolumeMount) {
	const volumeName = "host-proc-volume"
	return corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: path,
					Type: &hostPathDirectory,
				},
			},
		}, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: DefaultHostProcPath,
			ReadOnly:  true,
		}
}

// CustomHostKubeletVolume returns a new host path volume for custom kubelet path
// as well as corresponding mount used for non-root-enabler.
func CustomHostKubeletVolume(path string) (corev1.Volume, corev1.VolumeMount) {
	const volumeName = "host-kubelet-volume"
	return corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: path,
					Type: &hostPathDirectory,
				},
			},
		}, corev1.VolumeMount{
			Name:      volumeName,
			MountPath: path,
			ReadOnly:  false,
		}
}
