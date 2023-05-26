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

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
	spodv1alpha1 "sigs.k8s.io/security-profiles-operator/api/spod/v1alpha1"
)

const ProfilePartialLabel = "spo.x-k8s.io/partial"

type SecurityProfileBase interface {
	client.Object

	ListProfilesByRecording(ctx context.Context, cli client.Client, recording string) ([]metav1.Object, error)
	IsPartial() bool
	IsDisabled() bool
	IsReconcilable() bool
}

func IsPartial(obj metav1.Object) bool {
	_, ok := obj.GetLabels()[ProfilePartialLabel]
	return ok
}

func IsDisabled(prfSpec *SpecBase) bool {
	return prfSpec.Disabled
}

func IsReconcilable(prfBase SecurityProfileBase) bool {
	return !(prfBase.IsDisabled() || prfBase.IsPartial())
}

func ListProfilesByRecording(
	ctx context.Context,
	cli client.Client,
	recordingName string,
	recordingNamespace string,
	list client.ObjectList,
) ([]metav1.Object, error) {
	if err := cli.List(
		ctx,
		list,
		client.InNamespace(recordingNamespace),
		client.MatchingLabels{v1alpha1.ProfileToRecordingLabel: recordingName}); err != nil {
		return nil, fmt.Errorf("listing recorded profiles for %s: %w", recordingName, err)
	}

	recProfiles := make([]metav1.Object, 0)
	if err := meta.EachListItem(list, func(obj runtime.Object) error {
		if prf, ok := obj.(metav1.Object); ok {
			recProfiles = append(recProfiles, prf)
			return nil
		}
		return fmt.Errorf("object %T is not a metav1.Object", obj)
	}); err != nil {
		return nil, fmt.Errorf("iterating over partial profiles: %w", err)
	}

	return recProfiles, nil
}

// StatusBase contains common attributes for a profile's status.
type StatusBase struct {
	spodv1alpha1.ConditionedStatus `json:",inline"`
	Status                         secprofnodestatusv1alpha1.ProfileState `json:"status,omitempty"`
}

type StatusBaseUser interface {
	metav1.Object
	runtime.Object
	// GetStatusBase gets an instance of the Base status that the
	// profiles share
	GetStatusBase() *StatusBase
	// DeepCopyToStatusBaseIf exposes an interface to call deep copy
	// on this StatusBaseUser interface
	DeepCopyToStatusBaseIf() StatusBaseUser
	// Sets the needed status that's specific to the profile
	// implementation
	SetImplementationStatus()
}

// SpecBase contains common attributes for a profile's spec.
type SpecBase struct {
	// Whether the profile is disabled and should be skipped during reconciliation.
	// +kubebuilder:default=false
	Disabled bool `json:"disabled"`
}
