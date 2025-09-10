/*
Copyright 2021 The Kubernetes Authors.

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
	"go.podman.io/common/pkg/seccomp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

// DefaultLogEnricherProfile returns the default seccomp profile for log enricher.
func DefaultLogEnricherProfile() *seccompprofileapi.SeccompProfile {
	namespace := config.GetOperatorNamespace()
	labels := map[string]string{"app": config.OperatorName}

	return &seccompprofileapi.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.LogEnricherProfile,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: seccompprofileapi.SeccompProfileSpec{
			DefaultAction: seccomp.ActLog,
		},
	}
}
