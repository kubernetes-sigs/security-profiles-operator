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

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	secprofnodestatusv1alpha1 "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1alpha1"
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

		if _, ok := labels[secprofnodestatusv1alpha1.StatusToProfLabel]; ok {
			// the label is already set, nothing to do
			return nil
		}

		labels[secprofnodestatusv1alpha1.StatusToProfLabel] = util.KindBasedDNSLengthName(nsf.pol)
		nsf.pol.SetLabels(labels)

		return nsf.client.Update(ctx, nsf.pol)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) statusObj(
	polState secprofnodestatusv1alpha1.ProfileState,
) *secprofnodestatusv1alpha1.SecurityProfileNodeStatus {
	return &secprofnodestatusv1alpha1.SecurityProfileNodeStatus{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nsf.perNodeStatusName(),
			Namespace: nsf.pol.GetNamespace(),
			Labels: map[string]string{
				secprofnodestatusv1alpha1.StatusToProfLabel: util.KindBasedDNSLengthName(nsf.pol),
				secprofnodestatusv1alpha1.StatusToNodeLabel: nsf.nodeName,
				secprofnodestatusv1alpha1.StatusStateLabel:  string(polState),
				secprofnodestatusv1alpha1.StatusKindLabel:   nsf.pol.GetObjectKind().GroupVersionKind().Kind,
			},
		},
		NodeName: nsf.nodeName,
		Status:   polState,
	}
}

func (nsf *StatusClient) createNodeStatus(ctx context.Context) error {
	state := secprofnodestatusv1alpha1.ProfileStatePending
	if nsf.pol.IsPartial() {
		state = secprofnodestatusv1alpha1.ProfileStatePartial
	}
	s := nsf.statusObj(state)

	if setCtrlErr := controllerutil.SetControllerReference(nsf.pol, s, nsf.client.Scheme()); setCtrlErr != nil {
		return fmt.Errorf("cannot set node status owner reference: %s: %w", nsf.pol.GetName(), setCtrlErr)
	}
	err := nsf.client.Create(ctx, s)
	if err != nil && !kerrors.IsAlreadyExists(err) {
		return fmt.Errorf("creating node status: %w", err)
	}

	return nil
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
	err := c.Delete(ctx, nsf.statusObj(secprofnodestatusv1alpha1.ProfileStateTerminating))
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("deleting node status: %w", err)
	}

	return nil
}

func (nsf *StatusClient) Exists(ctx context.Context) (bool, error) {
	f := nsf.finalizerExists()
	s, err := nsf.nodeStatusExists(ctx)

	return s || f, err
}

func (nsf *StatusClient) finalizerExists() bool {
	return controllerutil.ContainsFinalizer(nsf.pol, nsf.finalizerString)
}

func (nsf *StatusClient) nodeStatusExists(ctx context.Context) (bool, error) {
	status := secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}
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
	polState secprofnodestatusv1alpha1.ProfileState,
) error {
	status := secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}
	err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
	if kerrors.IsNotFound(err) && polState == secprofnodestatusv1alpha1.ProfileStateTerminating {
		// it's OK if we're about to terminate a profile but it was already gone
		return nil
	} else if err != nil {
		return fmt.Errorf("retrieving the current status: %w", err)
	}

	status.Status = polState
	status.Labels[secprofnodestatusv1alpha1.StatusStateLabel] = string(polState)
	if err := nsf.client.Update(ctx, &status); err != nil {
		return fmt.Errorf("updating node status: %w", err)
	}

	return nil
}

func (nsf *StatusClient) Matches(
	ctx context.Context, polState secprofnodestatusv1alpha1.ProfileState,
) (bool, error) {
	status := secprofnodestatusv1alpha1.SecurityProfileNodeStatus{}
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		if kerrors.IsNotFound(err) && polState == secprofnodestatusv1alpha1.ProfileStateTerminating {
			// it's OK if we're about to terminate a profile but it was already gone
			return true, nil
		}
		return false, fmt.Errorf("getting node status for matching: %w", err)
	}
	return status.Status == polState, nil
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
	if polLabels == nil || polLabels[v1alpha1.ProfileToRecordingLabel] == "" {
		return nil
	}

	// if there are other policies recorded by the same recording, we don't need to do anything either
	otherPolicies, err := pol.ListProfilesByRecording(ctx, c, polLabels[v1alpha1.ProfileToRecordingLabel])
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

		if n := otherPol.GetName(); len(n) > 0 {
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

	profilerecording := &v1alpha1.ProfileRecording{}
	recordingName := util.NamespacedName(polLabels[v1alpha1.ProfileToRecordingLabel], pol.GetNamespace())
	err = c.Get(ctx, recordingName, profilerecording)
	if kerrors.IsNotFound(err) {
		return nil // should not happen, but if it does, we don't need to do anything
	} else if err != nil {
		return fmt.Errorf("getting profile recording: %w", err)
	}

	// no other recordings, remove the finalizer
	if !controllerutil.ContainsFinalizer(profilerecording, v1alpha1.RecordingHasUnmergedProfiles) {
		return nil
	}
	controllerutil.RemoveFinalizer(profilerecording, v1alpha1.RecordingHasUnmergedProfiles)
	return c.Update(ctx, profilerecording)
}
