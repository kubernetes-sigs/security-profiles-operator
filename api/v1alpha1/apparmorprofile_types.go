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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type AppArmorProfileSpec struct {
	Rules    string `json:"rules"`
	Enforced bool   `json:"enforced"`
}

type AppArmorProfile struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AppArmorProfileSpec   `json:"spec,omitempty"`
	Status AppArmorProfileStatus `json:"status,omitempty"`
}

type AppArmorProfileList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []AppArmorProfile `json:"items"`
}

// AppArmorProfileStatus contains status of the deployed AppArmorProfile.
type AppArmorProfileStatus struct {
	Path            string   `json:"path,omitempty"`
	Status          string   `json:"status,omitempty"`
	ActiveWorkloads []string `json:"activeWorkloads,omitempty"`
}

func init() { //nolint:gochecknoinits
	SchemeBuilder.Register(&AppArmorProfile{}, &AppArmorProfileList{})
}
