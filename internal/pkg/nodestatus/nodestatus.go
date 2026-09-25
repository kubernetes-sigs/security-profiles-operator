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

package nodestatus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

var log = logf.Log.WithName("nodestatus")

const (
	partialProfileFinalizer = "spo.x-k8s.io/partial-profile-finalizer"
)

type StatusClient struct {
	pol             profilebase.SecurityProfileBase
	nodeName        string
	finalizerString string
	client          client.Client

	// kind is the profile kind, resolved once on construction so that names
	// and labels do not depend on the TypeMeta of pol, which is empty for
	// objects decoded by the uncached typed client.
	kind string
}

// ErrNoNodeName is returned if the node name cannot be determined.
var ErrNoNodeName = errors.New("cannot determine node name")

// NewForProfile returns a status client for the node set in the node name
// environment variable.
func NewForProfile(pol profilebase.SecurityProfileBase, c client.Client) (*StatusClient, error) {
	nodeName, ok := os.LookupEnv(config.NodeNameEnvKey)
	if !ok {
		return nil, ErrNoNodeName
	}

	return NewForProfileOnNode(pol, c, nodeName)
}

// NewForProfileOnNode returns a status client for the provided node.
func NewForProfileOnNode(
	pol profilebase.SecurityProfileBase, c client.Client, nodeName string,
) (*StatusClient, error) {
	if nodeName == "" {
		return nil, ErrNoNodeName
	}

	kind, err := profileKind(pol, c)
	if err != nil {
		return nil, err
	}

	return &StatusClient{
		pol:             pol,
		kind:            kind,
		nodeName:        nodeName,
		finalizerString: getFinalizerString(pol, nodeName),
		client:          c,
	}, nil
}

// profileKind returns the kind of the profile. It falls back to the scheme if
// the TypeMeta is empty, which is the case for objects decoded by the uncached
// typed client.
func profileKind(pol profilebase.SecurityProfileBase, c client.Client) (string, error) {
	if kind := pol.GetObjectKind().GroupVersionKind().Kind; kind != "" {
		return kind, nil
	}

	if c == nil {
		return "", fmt.Errorf("cannot determine kind of profile %s without a client", pol.GetName())
	}

	gvk, err := apiutil.GVKForObject(pol, c.Scheme())
	if err != nil {
		return "", fmt.Errorf("cannot determine kind of profile %s: %w", pol.GetName(), err)
	}

	return gvk.Kind, nil
}

// profileID returns the value of the StatusToProfLabel for the profile.
func (nsf *StatusClient) profileID() string {
	return util.KindNameDNSLengthName(nsf.kind, nsf.pol.GetName())
}

func (nsf *StatusClient) perNodeStatusName() string {
	kind := strings.ToLower(nsf.kind)

	return util.DNSLengthName(kind, "%s-%s-%s", kind, nsf.pol.GetName(), nsf.nodeName)
}

func (nsf *StatusClient) perNodeStatusNamespacedName() types.NamespacedName {
	return util.NamespacedName(nsf.perNodeStatusName(), nsf.pol.GetNamespace())
}

func (nsf *StatusClient) Create(ctx context.Context) (bool, error) {
	if err := nsf.createFinalizer(ctx); err != nil {
		return false, fmt.Errorf("cannot create finalizer for %s: %w", nsf.pol.GetName(), err)
	}

	if err := nsf.createPolLabel(ctx); err != nil {
		return false, fmt.Errorf(
			"cannot create policy name label for %s: %w",
			nsf.pol.GetName(),
			err,
		)
	}

	wasMigrated, legacyState := nsf.removeLegacyNodeStatus(ctx)

	// if object does not exist, add it
	if err := nsf.createNodeStatus(ctx, legacyState); err != nil {
		return false, fmt.Errorf("cannot create node status for %s: %w", nsf.pol.GetName(), err)
	}

	return wasMigrated, nil
}

// removeLegacyNodeStatus removes old-format status objects that used
// <profileName>-<nodeName> instead of <kind>-<profileName>-<nodeName>.
// Returns true and the state of the legacy status if one was found and
// removed (upgrade migration).
func (nsf *StatusClient) removeLegacyNodeStatus(
	ctx context.Context,
) (bool, secprofnodestatusapi.ProfileState) {
	legacyName := nsf.pol.GetName() + "-" + nsf.nodeName
	if legacyName == nsf.perNodeStatusName() {
		return false, ""
	}

	old := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	key := util.NamespacedName(legacyName, nsf.pol.GetNamespace())

	if err := nsf.client.Get(ctx, key, old); err != nil {
		if !kerrors.IsNotFound(err) {
			log.Error(err, "failed to look up legacy node status", "name", legacyName)
		}

		return false, ""
	}

	// Verify the object belongs to this profile. A profile named
	// "<kind>-<other>" has a legacy name that collides with the
	// new-format name of profile "<other>".
	if old.Labels[secprofnodestatusapi.StatusToProfLabel] != nsf.profileID() {
		return false, ""
	}

	if err := nsf.client.Delete(ctx, old); err != nil && !kerrors.IsNotFound(err) {
		log.Error(err, "failed to remove legacy node status", "name", legacyName)

		return false, ""
	}

	return true, old.Status.Status
}

func (nsf *StatusClient) createFinalizer(ctx context.Context) error {
	return util.Retry(func() error {
		return util.AddFinalizer(ctx, nsf.client, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

func (nsf *StatusClient) createPolLabel(ctx context.Context) error {
	return util.Retry(func() error {
		// Re-fetch on every attempt: a failed update leaves the label in the
		// local object, and the retry must not mistake it for a stored one.
		if err := nsf.client.Get(ctx, client.ObjectKeyFromObject(nsf.pol), nsf.pol); err != nil {
			return fmt.Errorf("getting profile: %w", err)
		}

		labels := nsf.pol.GetLabels()
		if labels == nil {
			labels = make(map[string]string)
		}

		if _, ok := labels[secprofnodestatusapi.StatusToProfLabel]; ok {
			// the label is already set, nothing to do
			return nil
		}

		labels[secprofnodestatusapi.StatusToProfLabel] = nsf.profileID()
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
				secprofnodestatusapi.StatusToProfLabel: nsf.profileID(),
				secprofnodestatusapi.StatusToNodeLabel: nsf.nodeName,
				secprofnodestatusapi.StatusStateLabel:  string(polState),
				secprofnodestatusapi.StatusKindLabel:   nsf.kind,
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

// createNodeStatus creates the node status. A status migrated from a legacy
// status keeps the state of the legacy one, which tells for example whether
// the profile got installed on the node already.
func (nsf *StatusClient) createNodeStatus(
	ctx context.Context, legacyState secprofnodestatusapi.ProfileState,
) error {
	initialStatus := nsf.initialStatus()
	if initialStatus == secprofnodestatusapi.ProfileStatePending && legacyState != "" {
		initialStatus = legacyState
	}

	s := nsf.statusObj(initialStatus)

	if setCtrlErr := controllerutil.SetControllerReference(
		nsf.pol,
		s,
		nsf.client.Scheme(),
	); setCtrlErr != nil {
		return fmt.Errorf(
			"cannot set node status owner reference: %s: %w",
			nsf.pol.GetName(),
			setCtrlErr,
		)
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
	f := nsf.FinalizerExists()
	s, err := nsf.nodeStatusExists(ctx)

	return s && f, err
}

// FinalizerExists returns true if the profile carries the finalizer of this node.
func (nsf *StatusClient) FinalizerExists() bool {
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
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		status := secprofnodestatusapi.SecurityProfileNodeStatus{}

		err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status)
		if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
			// it's OK if we're about to terminate a profile but it was already gone
			return nil
		} else if err != nil {
			return fmt.Errorf("retrieving the current status: %w", err)
		}

		if status.Labels == nil {
			status.Labels = map[string]string{}
		}

		if status.Labels[secprofnodestatusapi.StatusStateLabel] != string(polState) {
			status.Labels[secprofnodestatusapi.StatusStateLabel] = string(polState)

			// The update refreshes the resource version of status, which
			// is required for the status update below. Reading it again
			// from the cache could return the previous version.
			if err := nsf.client.Update(ctx, &status); err != nil {
				return fmt.Errorf("updating node status labels: %w", err)
			}
		}

		if status.Status.Status == polState {
			return nil
		}

		status.Status.Status = polState
		if err := nsf.client.Status().Update(ctx, &status); err != nil {
			return fmt.Errorf("updating node status: %w", err)
		}

		return nil
	})
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

// State returns the state of the profile on the node.
func (nsf *StatusClient) State(ctx context.Context) (secprofnodestatusapi.ProfileState, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), &status); err != nil {
		return "", fmt.Errorf("getting node status: %w", err)
	}

	return status.Status.Status, nil
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

func handleRecordingFinalizer(
	ctx context.Context,
	c client.Client,
	pol profilebase.SecurityProfileBase,
) error {
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
	if !controllerutil.ContainsFinalizer(
		profilerecording,
		profilerecordingapi.RecordingHasUnmergedProfiles,
	) {
		return nil
	}

	controllerutil.RemoveFinalizer(
		profilerecording,
		profilerecordingapi.RecordingHasUnmergedProfiles,
	)

	return c.Update(ctx, profilerecording)
}
