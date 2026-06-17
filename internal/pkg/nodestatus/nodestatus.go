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

package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"os"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	partialProfileFinalizer = "spo.x-k8s.io/partial-profile-finalizer"
)

type StatusClient struct {
	pol             profilebase.SecurityProfileBase
	nodeName        string
	finalizerString string
	client          client.Client
}

func NewForProfile(pol profilebase.SecurityProfileBase, c client.Client) (*StatusClient, error) {
	nodeName, ok := os.LookupEnv(config.NodeNameEnvKey)
	if !ok {
		return nil, errors.New("cannot determine node name")
	}

	return &StatusClient{
		pol:             pol,
		nodeName:        nodeName,
		finalizerString: getFinalizerString(pol, nodeName),
		client:          c,
	}, nil
}

func (nsf *StatusClient) perNodeStatusName() string {
	return nsf.pol.GetName() + "-" + nsf.nodeName
}

func (nsf *StatusClient) perNodeStatusNamespacedName() types.NamespacedName {
	return util.NamespacedName(nsf.perNodeStatusName(), nsf.pol.GetNamespace())
}

func (nsf *StatusClient) Create(ctx context.Context) error {
	if err := nsf.createFinalizer(ctx); err != nil {
		return fmt.Errorf("cannot create finalizer for %s: %w", nsf.pol.GetName(), err)
	}

	if err := nsf.createPolLabel(ctx); err != nil {
		return fmt.Errorf("cannot create policy name label for %s: %w", nsf.pol.GetName(), err)
	}

	// if object does not exist, add it
	if err := nsf.createNodeStatus(ctx); err != nil {
		return fmt.Errorf("cannot create node status for %s: %w", nsf.pol.GetName(), err)
	}

	return nil
}

func (nsf *StatusClient) createFinalizer(ctx context.Context) error {
	return util.Retry(func() error {
		return util.AddFinalizer(ctx, nsf.client, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) createPolLabel(ctx context.Context) error {
	return util.Retry(func() error {
		labels := nsf.pol.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}

		if _, ok := labels[secprofnodestatusapi.StatusToProfLabel]; ok {
			// the label is already set, nothing to do
			return nil
		}

		labels[secprofnodestatusapi.StatusToProfLabel] = util.KindBasedDNSLengthName(nsf.pol)
		nsf.pol.SetLabels(labels)

		return nsf.client.Update(ctx, nsf.pol)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) statusObj(
	polState secprofnodestatusapi.ProfileState,
) *secprofnodestatusapi.SecurityProfileNodeStatus {
	return &secprofnodestatusapi.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsf.perNodeStatusName(),
			Namespace: nsf.pol.GetNamespace(),
			Labels: map[string]string{
				secprofnodestatusapi.StatusToProfLabel: util.KindBasedDNSLengthName(nsf.pol),
				secprofnodestatusapi.StatusToNodeLabel: nsf.nodeName,
				secprofnodestatusapi.StatusStateLabel:  string(polState),
				secprofnodestatusapi.StatusKindLabel:   nsf.pol.GetObjectKind().GroupVersionKind().Kind,
			},
		},
		Spec: secprofnodestatusapi.SecurityProfileNodeStatusSpec{
			NodeName: nsf.nodeName,
		},
		Status: secprofnodestatusapi.SecurityProfileNodeStatusStatus{
			Status: polState,
		},
	}
}

func (nsf *StatusClient) createNodeStatus(ctx context.Context) error {
	initialStatus := nsf.initialStatus()
	s := nsf.statusObj(initialStatus)

	if setCtrlErr := controllerutil.SetControllerReference(nsf.pol, s, nsf.client.Scheme()); setCtrlErr != nil {
		return fmt.Errorf("cannot set node status owner reference: %s: %w", nsf.pol.GetName(), setCtrlErr)
	}

	err := nsf.client.Create(ctx, s)
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating node status: %w", err)
	}

	if kerrors.IsAlreadyExists(err) {
		if getErr := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), s); getErr != nil {
			return fmt.Errorf("fetching existing node status: %w", getErr)
		}
	}

	s.Status.Status = initialStatus
	if updateErr := nsf.client.Status().Update(ctx, s); updateErr != nil {
		return fmt.Errorf("setting initial node status: %w", updateErr)
	}

	return nil
}

func (nsf *StatusClient) initialStatus() secprofnodestatusapi.ProfileState {
	if nsf.pol.IsDisabled() {
		return secprofnodestatusapi.ProfileStateDisabled
	} else if nsf.pol.IsPartial() {
		return secprofnodestatusapi.ProfileStatePartial
	}

	return secprofnodestatusapi.ProfileStatePending
}

func (nsf *StatusClient) Remove(ctx context.Context, c client.Client) error {
	// if finalizer exists, remove it
	if nsf.pol.IsPartial() {
		// list other profiles that are recorded by the same profileRecording
		// if there are no other profiles, remove the finalizer from the profileRecording
		if err := handleRecordingFinalizer(ctx, nsf.client, nsf.pol); err != nil {
			return fmt.Errorf("cannot remove node status/finalizer from seccomp profile: %w", err)
		}
	}

	if err := nsf.removeFinalizer(ctx); err != nil {
		return fmt.Errorf("cannot remove finalizer for %s: %w", nsf.pol.GetName(), err)
	}

	// if object exists, remove it
	if err := nsf.removeNodeStatus(ctx, c); err != nil {
		return fmt.Errorf("cannot remove nodeStatus for %s: %w", nsf.pol.GetName(), err)
	}

	return nil
}

func (nsf *StatusClient) removeFinalizer(ctx context.Context) error {
	return util.Retry(func() error {
		return util.RemoveFinalizer(ctx, nsf.client, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) removeNodeStatus(ctx context.Context, c client.Client) error {
	// the state here is more or less unused, we just care about the name since we're deleting...
	err := c.Delete(ctx, nsf.statusObj(secprofnodestatusapi.ProfileStateTerminating))
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("deleting node status: %w", err)
	}

	return nil
}

func (nsf *StatusClient) Exists(ctx context.Context) (bool, error) {
	f := nsf.finalizerExists()
	s, err := nsf.nodeStatusExists(ctx)

	return s && f, err
}

func (nsf *StatusClient) finalizerExists() bool {
	return controllerutil.ContainsFinalizer(nsf.pol, nsf.finalizerString)
}

func (nsf *StatusClient) nodeStatusExists(ctx context.Context) (bool, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
	if kerrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("fetching node status: %w", err)
	}

	return true, nil
}

func (nsf *StatusClient) SetNodeStatus(
	ctx context.Context,
	polState secprofnodestatusapi.ProfileState,
) error {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
	if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
		// it's OK if we're about to terminate a profile but it was already gone
		return nil
	} else if err != nil {
		return fmt.Errorf("retrieving the current status: %w", err)
	}

	status.Labels[secprofnodestatusapi.StatusStateLabel] = string(polState)
	if err := nsf.client.Update(ctx, &status); err != nil {
		return fmt.Errorf("updating node status labels: %w", err)
	}

	// Re-fetch to get the updated resourceVersion after the label update.
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		return fmt.Errorf("re-fetching node status: %w", err)
	}

	status.Status.Status = polState
	if err := nsf.client.Status().Update(ctx, &status); err != nil {
		return fmt.Errorf("updating node status: %w", err)
	}

	return nil
}

func (nsf *StatusClient) GetAnnotation(ctx context.Context, key string) (string, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		return "", fmt.Errorf("getting node status for annotation: %w", err)
	}

	if status.Annotations == nil {
		return "", nil
	}

	return status.Annotations[key], nil
}

func (nsf *StatusClient) SetAnnotation(ctx context.Context, key, value string) error {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		return fmt.Errorf("getting node status for annotation update: %w", err)
	}

	if status.Annotations == nil {
		status.Annotations = make(map[string]string)
	}

	if status.Annotations[key] == value {
		return nil
	}

	status.Annotations[key] = value

	if err := nsf.client.Update(ctx, &status); err != nil {
		return fmt.Errorf("updating node status annotation: %w", err)
	}

	return nil
}

func (nsf *StatusClient) Matches(
	ctx context.Context, polState secprofnodestatusapi.ProfileState,
) (bool, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
			// it's OK if we're about to terminate a profile but it was already gone
			return true, nil
		}

		return false, fmt.Errorf("getting node status for matching: %w", err)
	}

	return status.Status.Status == polState, nil
}

func getFinalizerString(pol profilebase.SecurityProfileBase, nodeName string) string {
	if pol.IsPartial() {
		return partialProfileFinalizer
	}

	finalizerString := util.GetFinalizerNodeString(nodeName)

	return finalizerString
}

func handleRecordingFinalizer(ctx context.Context, c client.Client, pol profilebase.SecurityProfileBase) error {
	// if this policy was not recorded, we don't need to do anything. This also covers the upgrade
	// case because the finalizer is only added when the policy is recorded with the new version
	polLabels := pol.GetLabels()
	if polLabels == nil {
		return nil
	}

	recordingName := polLabels[profilerecordingapi.ProfileToRecordingLabel]
	recordingNamespace := polLabels[profilerecordingapi.ProfileToRecordingNamespaceLabel]

	if recordingName == "" || recordingNamespace == "" {
		return nil
	}

	// if there are other policies recorded by the same recording, we don't need to do anything either
	otherPolicies, err := pol.ListProfilesByRecording(ctx, c, recordingName, recordingNamespace)
	if err != nil {
		return fmt.Errorf("listing profiles by recording: %w", err)
	}

	hasOthers := false

	for i := range otherPolicies {
		otherPol := otherPolicies[i]

		labels := otherPol.GetLabels()
		if labels == nil {
			continue
		}

		if !otherPol.GetDeletionTimestamp().IsZero() { // object is being deleted, don't count it
			continue
		}

		if _, ok := labels[profilebase.ProfilePartialLabel]; !ok { // not partial, don't count it
			continue
		}

		if n := otherPol.GetName(); n != "" {
			// we have a partial profile that is not being deleted and is not the current one
			if n != pol.GetName() {
				hasOthers = true

				break
			}
		}
	}

	// if there are other recordings, keep the finalizer
	if hasOthers {
		return nil
	}

	profilerecording := &profilerecordingapi.ProfileRecording{}

	err = c.Get(ctx, util.NamespacedName(recordingName, recordingNamespace), profilerecording)
	if kerrors.IsNotFound(err) {
		return nil // should not happen, but if it does, we don't need to do anything
	} else if err != nil {
		return fmt.Errorf("getting profile recording: %w", err)
	}

	// no other recordings, remove the finalizer
	if !controllerutil.ContainsFinalizer(profilerecording, profilerecordingapi.RecordingHasUnmergedProfiles) {
		return nil
	}

	controllerutil.RemoveFinalizer(profilerecording, profilerecordingapi.RecordingHasUnmergedProfiles)

	return c.Update(ctx, profilerecording)
}
