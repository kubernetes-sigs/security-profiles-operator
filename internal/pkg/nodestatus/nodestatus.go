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
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
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
	// legacyFinalizerString is the finalizer earlier releases added for a
	// node whose name does not fit into a finalizer, see
	// util.GetLegacyFinalizerNodeString. It is empty for every other node.
	legacyFinalizerString string
	client                client.Client

	// reader reads the profile after a conflict, see WithAPIReader.
	reader client.Reader

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
		pol:                   pol,
		kind:                  kind,
		nodeName:              nodeName,
		finalizerString:       getFinalizerString(pol, nodeName),
		legacyFinalizerString: getLegacyFinalizerString(pol, nodeName),
		client:                c,
	}, nil
}

// WithAPIReader sets the reader which the retries of a conflicting write of
// the finalizer read the profile with, usually the API reader of the manager.
// The cache may keep returning the version of the profile which conflicted.
// Without it, the retries read through the client.
func (nsf *StatusClient) WithAPIReader(reader client.Reader) {
	nsf.reader = reader
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
	if err := nsf.createFinalizerAndLabel(ctx); err != nil {
		return false, fmt.Errorf(
			"cannot create finalizer and policy name label for %s: %w",
			nsf.pol.GetName(),
			err,
		)
	}

	wasMigrated, legacyState, err := nsf.removeLegacyNodeStatus(ctx)
	if err != nil {
		return false, fmt.Errorf(
			"cannot remove legacy node status for %s: %w", nsf.pol.GetName(), err,
		)
	}

	// if object does not exist, add it
	if err := nsf.createNodeStatus(ctx, legacyState); err != nil {
		return false, fmt.Errorf("cannot create node status for %s: %w", nsf.pol.GetName(), err)
	}

	return wasMigrated, nil
}

// removeLegacyNodeStatus removes old-format status objects that used
// <profileName>-<nodeName> instead of <kind>-<profileName>-<nodeName>.
// Returns true and the state of the legacy status if one was found and
// removed (upgrade migration). Failing to look up or remove the legacy status
// is an error, so that the caller retries instead of leaving it behind.
func (nsf *StatusClient) removeLegacyNodeStatus(
	ctx context.Context,
) (bool, secprofnodestatusapi.ProfileState, error) {
	legacyName := nsf.pol.GetName() + "-" + nsf.nodeName
	if legacyName == nsf.perNodeStatusName() {
		return false, "", nil
	}

	old := &secprofnodestatusapi.SecurityProfileNodeStatus{}
	key := util.NamespacedName(legacyName, nsf.pol.GetNamespace())

	if err := nsf.client.Get(ctx, key, old); err != nil {
		if kerrors.IsNotFound(err) {
			return false, "", nil
		}

		return false, "", fmt.Errorf("looking up legacy node status %s: %w", legacyName, err)
	}

	// Verify the object belongs to this profile. A profile named
	// "<kind>-<other>" has a legacy name that collides with the
	// new-format name of profile "<other>".
	if old.Labels[secprofnodestatusapi.StatusToProfLabel] != nsf.profileID() {
		return false, "", nil
	}

	if err := nsf.client.Delete(ctx, old); err != nil && !kerrors.IsNotFound(err) {
		return false, "", fmt.Errorf("removing legacy node status %s: %w", legacyName, err)
	}

	return true, old.Status.Status, nil
}

// createFinalizer adds the finalizer of this node. A legacy finalizer of an
// earlier release is left in place, see MigrateLegacyFinalizer.
func (nsf *StatusClient) createFinalizer(ctx context.Context) error {
	return util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		return util.AddFinalizer(ctx, c, nsf.pol, nsf.finalizerString)
	}, util.IsNotFoundOrConflict)
}

// createFinalizerAndLabel adds the finalizer of this node and the label of
// the profile with a single patch. Every node does it for each profile at
// once, so the patch appends the finalizer instead of writing the whole
// profile, which would conflict with the other nodes, see
// util.AddFinalizerAndLabel.
func (nsf *StatusClient) createFinalizerAndLabel(ctx context.Context) error {
	return util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		// The profile is fetched again on every attempt, so a failed patch
		// does not leave changes in it which the retry would take for stored
		// ones.
		return util.AddFinalizerAndLabel(
			ctx,
			c,
			nsf.pol,
			nsf.finalizerString,
			secprofnodestatusapi.StatusToProfLabel,
			nsf.profileID(),
		)
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
				secprofnodestatusapi.StatusToNodeLabel: util.NodeNameLabelValue(nsf.nodeName),
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

// createNodeStatus creates the node status with all of its labels. A status
// migrated from a legacy status keeps the state of the legacy one, which tells
// for example whether the profile got installed on the node already. The API
// server drops the status of a created object, so the state takes a second
// write, unless an existing status has it already.
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
		existing := &secprofnodestatusapi.SecurityProfileNodeStatus{}
		if getErr := nsf.client.Get(
			ctx,
			nsf.perNodeStatusNamespacedName(),
			existing,
		); getErr != nil {
			return fmt.Errorf("fetching existing node status: %w", getErr)
		}

		// The status may be left over from a profile of the same name which
		// got deleted, so its owner and labels become the ones of this
		// profile. The garbage collector would delete it otherwise.
		if !equality.Semantic.DeepEqual(existing.OwnerReferences, s.OwnerReferences) ||
			!labels.SelectorFromSet(s.Labels).Matches(labels.Set(existing.Labels)) {
			if existing.Labels == nil {
				existing.Labels = map[string]string{}
			}

			maps.Copy(existing.Labels, s.Labels)
			existing.OwnerReferences = s.OwnerReferences

			if updateErr := nsf.client.Update(ctx, existing); updateErr != nil {
				return fmt.Errorf("updating existing node status: %w", updateErr)
			}
		}

		s = existing
	}

	if s.Status.Status == initialStatus && s.Status.Message == "" {
		return nil
	}

	base := s.DeepCopy()
	s.Status.Status = initialStatus
	s.Status.Message = ""

	if patchErr := nsf.client.Status().Patch(ctx, s, client.MergeFrom(base)); patchErr != nil {
		return fmt.Errorf("setting initial node status: %w", patchErr)
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

// Remove removes the finalizer of the node from the profile and deletes the
// node status. The has-unmerged-profiles finalizer on the recording of a
// partial profile is left to the recording merger of the manager, which checks
// the partial profiles of every kind before it releases the recording.
func (nsf *StatusClient) Remove(ctx context.Context, c client.Client) error {
	if err := nsf.removeFinalizer(ctx); err != nil {
		return fmt.Errorf("cannot remove finalizer for %s: %w", nsf.pol.GetName(), err)
	}

	// if object exists, remove it
	if err := nsf.removeNodeStatus(ctx, c); err != nil {
		return fmt.Errorf("cannot remove nodeStatus for %s: %w", nsf.pol.GetName(), err)
	}

	return nil
}

// MigrateLegacyFinalizer adds the current finalizer of this node to a profile
// which carries the finalizer earlier releases added for a node whose name
// does not fit into a finalizer. It does nothing unless the profile carries the
// legacy finalizer.
//
// The legacy finalizer is kept: it is shared by all nodes whose names start
// with the same truncated prefix, and some of them may not have added their
// own finalizer yet. It is removed along with the current one when the profile
// is removed from the node, see Remove.
//
// Known limitation, as in earlier releases: the first of the nodes sharing
// the legacy finalizer which removes the profile also removes the legacy
// finalizer. A node which has not migrated yet then has no finalizer on the
// profile anymore, so the profile can go away before that node removed it.
// Nodes which migrated keep the profile through their own finalizer.
func (nsf *StatusClient) MigrateLegacyFinalizer(ctx context.Context) error {
	if nsf.legacyFinalizerString == "" ||
		!controllerutil.ContainsFinalizer(nsf.pol, nsf.legacyFinalizerString) ||
		controllerutil.ContainsFinalizer(nsf.pol, nsf.finalizerString) {
		return nil
	}

	if err := nsf.createFinalizer(ctx); err != nil {
		return fmt.Errorf(
			"adding the finalizer next to the legacy one of %s: %w",
			nsf.pol.GetName(),
			err,
		)
	}

	return nil
}

// removeFinalizer removes the finalizer of this node and the legacy one of
// earlier releases, which other nodes may share, see MigrateLegacyFinalizer.
func (nsf *StatusClient) removeFinalizer(ctx context.Context) error {
	return util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		return util.RemoveFinalizers(
			ctx, c, nsf.pol, nsf.finalizerString, nsf.legacyFinalizerString,
		)
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

// FinalizerExists returns true if the profile carries the finalizer of this
// node, in its current or its legacy form: a profile which was being deleted
// before the upgrade still has to be removed from the node.
func (nsf *StatusClient) FinalizerExists() bool {
	return controllerutil.ContainsFinalizer(nsf.pol, nsf.finalizerString) ||
		(nsf.legacyFinalizerString != "" &&
			controllerutil.ContainsFinalizer(nsf.pol, nsf.legacyFinalizerString))
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

// SetNodeStatus sets the state of the node status and clears its message.
func (nsf *StatusClient) SetNodeStatus(
	ctx context.Context,
	polState secprofnodestatusapi.ProfileState,
) error {
	return nsf.SetNodeStatusWithMessage(ctx, polState, "")
}

// SetNodeStatusWithMessage sets the state of the node status along with a
// message which tells why the profile is in that state, like the reason why
// it failed to install. A message longer than the API allows is truncated.
//
// Only the daemon of this node writes its status, so the state label and the
// status are written with patches which do not carry the resource version.
// They cannot conflict, and the status does not depend on the resource
// version which the label write returns. Nothing gets written if the state
// and the message are set already.
func (nsf *StatusClient) SetNodeStatusWithMessage(
	ctx context.Context,
	polState secprofnodestatusapi.ProfileState,
	message string,
) error {
	message = truncateMessage(message)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.client.Get(ctx, nsf.perNodeStatusNamespacedName(), status)
	if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
		// it's OK if we're about to terminate a profile but it was already gone
		return nil
	} else if err != nil {
		return fmt.Errorf("retrieving the current status: %w", err)
	}

	if status.Labels[secprofnodestatusapi.StatusStateLabel] != string(polState) {
		base := status.DeepCopy()

		if status.Labels == nil {
			status.Labels = map[string]string{}
		}

		status.Labels[secprofnodestatusapi.StatusStateLabel] = string(polState)

		if err := nsf.client.Patch(ctx, status, client.MergeFrom(base)); err != nil {
			return fmt.Errorf("updating node status labels: %w", err)
		}
	}

	if status.Status.Status == polState && status.Status.Message == message {
		return nil
	}

	// The status read from the cache can lag behind the stored one, so the
	// patch sets both fields instead of the difference to the cached status.
	// A null message removes an earlier one.
	var messageValue any
	if message != "" {
		messageValue = message
	}

	patch, err := json.Marshal(map[string]any{
		"status": map[string]any{"status": polState, "message": messageValue},
	})
	if err != nil {
		return fmt.Errorf("marshaling node status patch: %w", err)
	}

	if err := nsf.client.Status().Patch(
		ctx, status, client.RawPatch(types.MergePatchType, patch),
	); err != nil {
		return fmt.Errorf("updating node status: %w", err)
	}

	return nil
}

// truncateMessage shortens the message to the length the API allows for the
// message of a node status.
func truncateMessage(message string) string {
	if utf8.RuneCountInString(message) <= secprofnodestatusapi.MaxMessageLength {
		return message
	}

	const ellipsis = "..."

	runes := []rune(message)

	return string(runes[:secprofnodestatusapi.MaxMessageLength-len(ellipsis)]) + ellipsis
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

// SetAnnotation sets the annotation on the node status of the profile. A
// conflict with another writer of the status, like SetNodeStatus running for
// the same profile, is retried.
func (nsf *StatusClient) SetAnnotation(ctx context.Context, key, value string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
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
	})
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

// getLegacyFinalizerString returns the finalizer which earlier releases added
// for the node, if it differs from the current one.
func getLegacyFinalizerString(pol profilebase.SecurityProfileBase, nodeName string) string {
	if pol.IsPartial() {
		return ""
	}

	return util.GetLegacyFinalizerNodeString(nodeName)
}
