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
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

var (
	falsely                         = false
	truly                           = true
	userRoot                  int64 = 0
	userRootless              int64 = 2000
	hostPathDirectory               = v1.HostPathDirectory
	hostPathDirectoryOrCreate       = v1.HostPathDirectoryOrCreate
)

const operatorRoot = "/var/lib/security-profiles-operator"

var Manifest = &appsv1.DaemonSet{
	ObjectMeta: metav1.ObjectMeta{
		Name:      config.OperatorName,
		Namespace: config.OperatorName,
	},
	Spec: appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "spod"},
		},
		Template: v1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					"openshift.io/scc":         "privileged",
					v1.SeccompPodAnnotationKey: v1.SeccompProfileRuntimeDefault,
					v1.SeccompContainerAnnotationKeyPrefix + config.OperatorName: "localhost/security-profiles-operator.json",
				},
				Labels: map[string]string{
					"app": "spod",
				},
			},
			Spec: v1.PodSpec{
				ServiceAccountName: config.SPOdServiceAccount,
				InitContainers: []v1.Container{{
					Name: "non-root-enabler",
					// Creates directory /var/lib/security-profiles-operator,
					// sets 2000:2000 as its owner and symlink it to
					// /var/lib/kubelet/seccomp/operator. This is required
					// to allow the main container to run as non-root.
					Command: []string{"bash", "-c"},
					Args: []string{`
						set -euo pipefail

						if [ ! -d ` + config.KubeletSeccompRootPath + ` ]; then
							/bin/mkdir -m 0744 -p ` + config.KubeletSeccompRootPath + `
						fi

						/bin/mkdir -p ` + operatorRoot + `
						/bin/chmod 0744 ` + operatorRoot + `

						if [ ! -L ` + config.ProfilesRootPath + ` ]; then
							/bin/ln -s ` + operatorRoot + ` ` + config.ProfilesRootPath + `
						fi

						/bin/chown -R 2000:2000 ` + operatorRoot + `
						cp -f -v /opt/seccomp-profiles/* ` + config.KubeletSeccompRootPath + `
					`},
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-varlib-volume",
							MountPath: "/var/lib",
						},
						{
							Name:      "profile-configmap-volume",
							MountPath: "/opt/seccomp-profiles",
							ReadOnly:  true,
						},
					},
					SecurityContext: &v1.SecurityContext{
						AllowPrivilegeEscalation: &falsely,
						ReadOnlyRootFilesystem:   &truly,
						Capabilities: &v1.Capabilities{
							Drop: []v1.Capability{"ALL"},
							Add:  []v1.Capability{"CHOWN", "FOWNER", "FSETID", "DAC_OVERRIDE"},
						},
						RunAsUser: &userRoot,
						SELinuxOptions: &v1.SELinuxOptions{
							// TODO(jaosorior): Use a more restricted selinux type
							Type: "spc_t",
						},
					},
					Resources: v1.ResourceRequirements{
						Requests: v1.ResourceList{
							v1.ResourceMemory:           resource.MustParse("32Mi"),
							v1.ResourceCPU:              resource.MustParse("100m"),
							v1.ResourceEphemeralStorage: resource.MustParse("10Mi"),
						},
						Limits: v1.ResourceList{
							v1.ResourceMemory:           resource.MustParse("64Mi"),
							v1.ResourceCPU:              resource.MustParse("250m"),
							v1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
						},
					},
				}},
				Containers: []v1.Container{{
					Name:            config.OperatorName,
					Args:            []string{"daemon"},
					ImagePullPolicy: v1.PullAlways,
					VolumeMounts: []v1.VolumeMount{
						{
							Name:      "host-operator-volume",
							MountPath: config.ProfilesRootPath,
						},
					},
					SecurityContext: &v1.SecurityContext{
						AllowPrivilegeEscalation: &falsely,
						ReadOnlyRootFilesystem:   &truly,
						Capabilities: &v1.Capabilities{
							Drop: []v1.Capability{"ALL"},
						},
						RunAsUser:  &userRootless,
						RunAsGroup: &userRootless,
						SELinuxOptions: &v1.SELinuxOptions{
							// TODO(jaosorior): Use a more restricted selinux type
							Type: "spc_t",
						},
					},
					Resources: v1.ResourceRequirements{
						Requests: v1.ResourceList{
							v1.ResourceMemory:           resource.MustParse("64Mi"),
							v1.ResourceCPU:              resource.MustParse("100m"),
							v1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
						},
						Limits: v1.ResourceList{
							v1.ResourceMemory:           resource.MustParse("128Mi"),
							v1.ResourceCPU:              resource.MustParse("300m"),
							v1.ResourceEphemeralStorage: resource.MustParse("200Mi"),
						},
					},
					Env: []v1.EnvVar{
						{
							Name: config.NodeNameEnvKey,
							ValueFrom: &v1.EnvVarSource{
								FieldRef: &v1.ObjectFieldSelector{
									FieldPath: "spec.nodeName",
								},
							},
						},
					},
				}},
				Volumes: []v1.Volume{
					// /var/lib is used as symlinks cannot be created across
					// different volumes
					{
						Name: "host-varlib-volume",
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/var/lib",
								Type: &hostPathDirectory,
							},
						},
					},
					{
						Name: "host-operator-volume",
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{
								Path: "/var/lib/security-profiles-operator",
								Type: &hostPathDirectoryOrCreate,
							},
						},
					},
					{
						Name: "profile-configmap-volume",
						VolumeSource: v1.VolumeSource{
							ConfigMap: &v1.ConfigMapVolumeSource{
								LocalObjectReference: v1.LocalObjectReference{
									Name: "security-profiles-operator-profile",
								},
							},
						},
					},
				},
				Tolerations: []v1.Toleration{
					{
						Effect: v1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/master",
					},
					{
						Effect: v1.TaintEffectNoSchedule,
						Key:    "node-role.kubernetes.io/control-plane",
					},
					{
						Effect:   v1.TaintEffectNoExecute,
						Key:      "node.kubernetes.io/not-ready",
						Operator: v1.TolerationOpExists,
					},
				},
				NodeSelector: map[string]string{
					"kubernetes.io/os": "linux",
				},
			},
		},
	},
}
