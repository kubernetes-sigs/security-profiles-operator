/*
Copyright The Kubernetes Authors.

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
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	spodapi "sigs.k8s.io/security-profiles-operator/api/spod/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	userRoot                           int64
	falsely                            = false
	truly                              = true
	userRootless                       = int64(config.UserRootless)
	hostPathDirectory                  = corev1.HostPathDirectory
	hostPathDirectoryOrCreate          = corev1.HostPathDirectoryOrCreate
	healthzPath                        = "/healthz"
	openshiftCertAnnotation            = "service.beta.openshift.io/serving-cert-secret-name"
	localSeccompProfilePath            = LocalSeccompProfilePath
	localSeccompBpfRecorderProfilePath = LocalSeccompBpfRecorderProfilePath

	// kubeletDirVolume is the seccomp directory of the host kubelet root
	// directory known to the operator, which the non-root enabler mounts
	// below config.HostRoot.
	kubeletDirVolume, kubeletDirVolumeMount = KubeletDirVolume(
		KubeletDirVolumeName, config.KubeletDir(),
	)

	// serviceAccountTokenVolume is the projected service account token which
	// only the containers talking to the API server mount, instead of the
	// automatically mounted token in every container.
	serviceAccountTokenVolume, serviceAccountTokenVolumeMount = ServiceAccountTokenVolume()
)

const (
	HomeDirectory                                    = "/home"
	TempDirectory                                    = "/tmp"
	SelinuxDropDirectory                             = "/etc/selinux.d"
	SelinuxdPrivateDir                               = "/var/run/selinuxd"
	SelinuxdSocketPath                               = SelinuxdPrivateDir + "/selinuxd.sock"
	SelinuxdDBPath                                   = SelinuxdPrivateDir + "/selinuxd.db"
	sysKernelDebugPath                               = "/sys/kernel/debug"
	sysKernelSecurityPath                            = "/sys/kernel/security"
	sysKernelTracingPath                             = "/sys/kernel/tracing"
	InitContainerIDNonRootenabler                    = 0
	InitContainerIDSelinuxSharedPoliciesCopier       = 1
	ContainerIDDaemon                                = 0
	ContainerIDSelinuxd                              = 1
	ContainerIDLogEnricher                           = 2
	ContainerIDBpfRecorder                           = 3
	ContainerIDJsonEnricher                          = 4
	DefaultHostProcPath                              = "/proc"
	SelinuxContainerName                             = "selinuxd"
	LogEnricherContainerName                         = "log-enricher"
	DefaultLogEnricherSource                         = spodapi.LogEnricherSourceAuditd
	JsonEnricherContainerName                        = "json-enricher"
	BpfRecorderContainerName                         = "bpf-recorder"
	NonRootEnablerContainerName                      = "non-root-enabler"
	SelinuxPoliciesCopierContainerName               = "selinux-shared-policies-copier"
	LocalSeccompProfilePath                          = "security-profiles-operator.json"
	LocalSeccompBpfRecorderProfilePath               = "bpf-recorder.json"
	DefaultPriorityClassName                         = "system-node-critical"
	servicePort                                int32 = 443
	ContainerPort                              int32 = 9443
	metricsServerCert                                = "metrics-server-cert"
	MetricsCertPath                                  = "/var/run/secrets/metrics"
	SelinuxCustomTemplatesVolumeName                 = "selinux-custom-templates"
	SelinuxModuleStorePath                           = "/var/lib/selinux"
	labelApp                                         = "app"
	labelName                                        = "name"
	selinuxTypeSpcT                                  = "spc_t"
	KubeletDirVolumeName                             = "host-kubelet-dir-volume"
	ServiceAccountTokenVolumeName                    = "kube-api-access"
	//nolint:gosec // a path, no credential
	serviceAccountTokenMountPath               = "/var/run/secrets/kubernetes.io/serviceaccount"
	serviceAccountTokenExpirationSeconds int64 = 3607

	// CapabilityAll drops all capabilities of a container.
	CapabilityAll corev1.Capability = "ALL"

	// DefaultSelinuxTypeTag is the SELinux type of the SPOd containers if
	// the SPOD does not configure one.
	DefaultSelinuxTypeTag = selinuxTypeSpcT
)

var DefaultSPOD = &spodapi.SecurityProfilesOperatorDaemon{
	ObjectMeta: metav1.ObjectMeta{
		Name:   config.SPOdName,
		Labels: map[string]string{labelApp: config.OperatorName},
	},
	Spec: spodapi.SPODSpec{
		Verbosity:                   0,
		EnableProfiling:             new(bool),
		EnableMemoryOptimization:    new(bool),
		EnableInsecureMetricsAccess: new(bool),
		EnableAppArmor:              new(bool),
		HostProcVolumePath:          DefaultHostProcPath,
		Selinux: spodapi.SPODSelinuxConfig{
			Options: spodapi.SelinuxOptions{
				AllowedSystemProfiles: []string{
					"container",
				},
			},
		},
		Enricher: spodapi.SPODEnricherConfig{
			EnableLogEnricher:  new(bool),
			EnableJsonEnricher: new(bool),
			EnableBpfRecorder:  new(bool),
			EnableExecMetadata: new(true),
			LogEnricherSource:  DefaultLogEnricherSource,
		},
		Webhook: spodapi.SPODWebhookConfig{
			StaticConfig: new(bool),
		},
		Security: spodapi.SPODSecurityConfig{
			DisableOCIArtifactSignatureVerification: new(bool),
		},
		Scheduling: spodapi.SPODSchedulingConfig{
			PriorityClassName: DefaultPriorityClassName,
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
				labelApp:  config.OperatorName,
				labelName: config.SPOdName,
			},
		},
		Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					// The containers of the SPOd require host access, so pin
					// the privileged SCC on OpenShift.
					openshiftRequiredSCCAnnotation: "privileged",
				},
				Labels: map[string]string{
					labelApp:  config.OperatorName,
					labelName: config.SPOdName,
				},
			},
			Spec: corev1.PodSpec{
				ServiceAccountName: config.SPOdServiceAccount,
				// Only the containers which talk to the API server mount
				// the service account token, see serviceAccountTokenVolume.
				AutomountServiceAccountToken: &falsely,
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
					FSGroup: &userRootless,
				},
				InitContainers: []corev1.Container{
					{
						Name:            NonRootEnablerContainerName,
						Args:            []string{"non-root-enabler"},
						ImagePullPolicy: corev1.PullAlways,
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "host-operator-volume",
								MountPath: config.OperatorRoot,
							},
							{
								Name:      "operator-profiles-volume",
								MountPath: "/opt/spo-profiles",
								ReadOnly:  true,
							},
							kubeletDirVolumeMount,
							// The enabler reads the kubelet directory label
							// of its node.
							serviceAccountTokenVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
								Add: []corev1.Capability{
									"CHOWN",
									"FOWNER",
									"DAC_OVERRIDE",
								},
							},
							RunAsUser: &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
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
semodule -R
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
							AllowPrivilegeEscalation: &truly,
							ReadOnlyRootFilesystem:   &truly,
							Privileged:               &truly, // Required for semodule -R to reload the kernel policy
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
								Add: []corev1.Capability{
									"CHOWN",
									"FOWNER",
									"FSETID",
									"DAC_OVERRIDE",
								},
							},
							RunAsUser: &userRoot,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
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
							{
								Name:      "metrics-cert-volume",
								MountPath: MetricsCertPath,
								ReadOnly:  true,
							},
							serviceAccountTokenVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &falsely,
							ReadOnlyRootFilesystem:   &truly,
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
							},
							RunAsUser:  &userRootless,
							RunAsGroup: &userRootless,
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(jaosorior): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
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
								Name: config.OperatorNamespaceEnvKey,
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
							{
								Name: config.PodNameEnvKey,
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "metadata.name",
									},
								},
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
							FailureThreshold: 10,
							PeriodSeconds:    3,
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
							PeriodSeconds:    10,
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
								Add: []corev1.Capability{
									"CHOWN",
									"FOWNER",
									"FSETID",
									"DAC_OVERRIDE",
								},
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
							serviceAccountTokenVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							Privileged:             &falsely,
							RunAsUser:              &userRoot,
							RunAsGroup:             &userRoot,
							// The runtime default AppArmor profile denies the
							// ptrace read access to the host processes.
							AppArmorProfile: &corev1.AppArmorProfile{
								Type: corev1.AppArmorProfileTypeUnconfined,
							},
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
								// The enricher resolves the processes of the
								// host PID namespace through /proc, which
								// requires ptrace access to processes of other
								// users and read access to their root owned
								// files. It hands its GRPC socket over to the
								// rootless daemon. The BPF source adds the
								// capabilities to load and attach its programs.
								Add: []corev1.Capability{
									"SYS_PTRACE",
									"DAC_READ_SEARCH",
									"CHOWN",
								},
							},
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(pjbgf): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
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
								Name:      "sys-kernel-security-volume",
								MountPath: sysKernelSecurityPath,
								ReadOnly:  true,
							},
							{
								Name:      "sys-kernel-tracing-volume",
								MountPath: sysKernelTracingPath,
								ReadOnly:  true,
							},
							{
								Name:      "grpc-server-volume",
								MountPath: filepath.Dir(config.GRPCServerSocketBpfRecorder),
							},
							serviceAccountTokenVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							Privileged:             &falsely,
							// Without no_new_privs the OCI runtime applies
							// the seccomp profile before it switches the
							// user and group, which the profile does not
							// allow.
							AllowPrivilegeEscalation: &falsely,
							RunAsUser:                &userRoot,
							RunAsGroup:               &userRoot,
							// The runtime default AppArmor profile denies the
							// ptrace read access to the host processes. The SPOd
							// uses the AppArmor profile of the recorder instead
							// if AppArmor is enabled.
							AppArmorProfile: &corev1.AppArmorProfile{
								Type: corev1.AppArmorProfileTypeUnconfined,
							},
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
								Add: []corev1.Capability{
									"BPF",             // Required to load the BPF programs
									"PERFMON",         // Required to attach the tracepoints
									"SYS_RESOURCE",    // Required to raise the locked memory limit
									"SYS_PTRACE",      // Required to read /proc of host processes
									"DAC_READ_SEARCH", // Required by open_by_handle_at on host files
									"CHOWN",           // Required to hand the GRPC socket to the daemon
								},
							},
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(pjbgf): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
							},
							SeccompProfile: &corev1.SeccompProfile{
								Type:             corev1.SeccompProfileTypeLocalhost,
								LocalhostProfile: &localSeccompBpfRecorderProfilePath,
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
						Name: JsonEnricherContainerName,
						Args: []string{
							"json-enricher",
						},
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
								Name:      "sys-kernel-debug-volume",
								MountPath: sysKernelDebugPath,
								ReadOnly:  true,
							},
							{
								Name:      "sys-kernel-tracing-volume",
								MountPath: sysKernelTracingPath,
								ReadOnly:  true,
							},
							serviceAccountTokenVolumeMount,
						},
						SecurityContext: &corev1.SecurityContext{
							ReadOnlyRootFilesystem: &truly,
							Privileged:             &falsely,
							RunAsUser:              &userRoot,
							RunAsGroup:             &userRoot,
							// The runtime default AppArmor profile denies the
							// ptrace read access to the host processes.
							AppArmorProfile: &corev1.AppArmorProfile{
								Type: corev1.AppArmorProfileTypeUnconfined,
							},
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{CapabilityAll},
								Add: []corev1.Capability{
									"SYS_PTRACE",      // Needed for /proc/PID/environ on some systems
									"SYS_RESOURCE",    // Needed for BPF enablement
									"BPF",             // Required to use BPF
									"PERFMON",         // Required to attach tracepoint in BPF
									"DAC_READ_SEARCH", // Required to read the root owned files of host processes
								},
							},
							SELinuxOptions: &corev1.SELinuxOptions{
								// TODO(pjbgf): Use a more restricted selinux type
								Type: selinuxTypeSpcT,
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
				},
				Volumes: []corev1.Volume{
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
						Name: "sys-kernel-security-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: sysKernelSecurityPath,
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "sys-kernel-tracing-volume",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: sysKernelTracingPath,
								Type: &hostPathDirectory,
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
					kubeletDirVolume,
					{
						Name: "home-volume",
						VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						},
					},
					serviceAccountTokenVolume,
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
			labelApp:  config.OperatorName,
			labelName: config.SPOdName,
		},
	},
	Spec: corev1.ServiceSpec{
		Ports: []corev1.ServicePort{
			{
				Name:       "http",
				Port:       servicePort,
				TargetPort: intstr.FromInt32(ContainerPort),
			},
		},
		Selector: map[string]string{
			labelApp:  config.OperatorName,
			labelName: config.SPOdName,
		},
	},
}

func CustomLogVolume(
	mountPath string,
	logVolumeSource *corev1.VolumeSource,
) (corev1.Volume, corev1.VolumeMount) {
	const volumeName = "json-enricher-log-output-volume"

	volume := corev1.Volume{
		Name:         volumeName,
		VolumeSource: *logVolumeSource,
	}
	mount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: mountPath,
		ReadOnly:  false,
	}

	return volume, mount
}

// KubeletDirVolume returns a hostPath volume with the given name for the
// seccomp directory of the kubelet root directory dir on the host, as well as
// the corresponding mount for the non-root enabler. Only the seccomp directory
// is mounted, because it is the only part of the kubelet directory the
// non-root enabler touches, while the rest of it holds the secret volumes of
// every pod on the node. The mount keeps the host path below config.HostRoot,
// which is where the non-root enabler expects the kubelet directory.
// DirectoryOrCreate is used because the operator cannot know which of the
// configured kubelet directories exist on a given node.
func KubeletDirVolume(name, dir string) (corev1.Volume, corev1.VolumeMount) {
	seccompDir := kubeletSeccompDir(dir)

	volume := corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: seccompDir,
				Type: &hostPathDirectoryOrCreate,
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      name,
		MountPath: filepath.Join(config.HostRoot, seccompDir),
	}

	return volume, mount
}

// kubeletSeccompDir returns the seccomp directory of the kubelet root
// directory dir.
func kubeletSeccompDir(dir string) string {
	return filepath.Join(dir, config.SeccompProfilesFolder)
}

// KubeletDirFromVolume returns the kubelet root directory of a volume created
// by KubeletDirVolume, and false if the volume is not one.
func KubeletDirFromVolume(volume *corev1.Volume) (string, bool) {
	if volume.HostPath == nil || !strings.HasPrefix(volume.Name, KubeletDirVolumeName) {
		return "", false
	}

	dir, ok := strings.CutSuffix(volume.HostPath.Path, "/"+config.SeccompProfilesFolder)
	if !ok || dir == "" {
		return "", false
	}

	return dir, true
}

// ServiceAccountTokenVolume returns the projected service account token
// volume and its mount, which replace the automatically mounted token of the
// SPOd pod. The projection matches the one of the kubelet, so that the client
// libraries find the token, the CA and the namespace at the usual paths.
func ServiceAccountTokenVolume() (corev1.Volume, corev1.VolumeMount) {
	volume := corev1.Volume{
		Name: ServiceAccountTokenVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: ptr.To[int32](0o644),
				Sources: []corev1.VolumeProjection{
					{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Path:              "token",
							ExpirationSeconds: new(serviceAccountTokenExpirationSeconds),
						},
					},
					{
						ConfigMap: &corev1.ConfigMapProjection{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "kube-root-ca.crt",
							},
							Items: []corev1.KeyToPath{
								{Key: "ca.crt", Path: "ca.crt"},
							},
						},
					},
					{
						DownwardAPI: &corev1.DownwardAPIProjection{
							Items: []corev1.DownwardAPIVolumeFile{{
								Path: "namespace",
								FieldRef: &corev1.ObjectFieldSelector{
									APIVersion: "v1",
									FieldPath:  "metadata.namespace",
								},
							}},
						},
					},
				},
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      ServiceAccountTokenVolumeName,
		MountPath: serviceAccountTokenMountPath,
		ReadOnly:  true,
	}

	return volume, mount
}

// CustomHostProcVolume returns a new host /proc path volume as well as
// corresponding mount used for the log-enricher or bpf-recorder.
func CustomHostProcVolume(path string) (corev1.Volume, corev1.VolumeMount) {
	const volumeName = "host-proc-volume"

	volume := corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: path,
				Type: &hostPathDirectory,
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      volumeName,
		MountPath: DefaultHostProcPath,
		ReadOnly:  true,
	}

	return volume, mount
}

func CustomTemplatesVolume(configMapName string) (corev1.Volume, corev1.VolumeMount) {
	volume := corev1.Volume{
		Name: SelinuxCustomTemplatesVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
			},
		},
	}
	mount := corev1.VolumeMount{
		Name:      SelinuxCustomTemplatesVolumeName,
		MountPath: "/usr/share/selinuxd/templates",
		ReadOnly:  true,
	}

	return volume, mount
}
