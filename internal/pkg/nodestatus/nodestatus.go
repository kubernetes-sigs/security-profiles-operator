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
	"strings"
	"sync"
	"unicode/utf8"

	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	secprofnodestatusapi "sigs.k8s.io/security-profiles-operator/api/secprofnodestatus/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	partialProfileFinalizer = "spo.x-k8s.io/partial-profile-finalizer"

	// annotationPrefix is the prefix of the annotations which the daemon
	// keeps on the node status, like whether it installed the profile.
	annotationPrefix = "spo.x-k8s.io/"

	// UnsupportedLabel marks the node status of a node which does not
	// support the kind of the profile, like a node without AppArmor. The
	// manager leaves such a status out of the state of the profile, see
	// MarkUnsupported.
	UnsupportedLabel = "spo.x-k8s.io/kind-unsupported"
)

// IsUnsupported returns true if the node status belongs to a node which does
// not support the kind of the profile, see MarkUnsupported.
func IsUnsupported(status *secprofnodestatusapi.SecurityProfileNodeStatus) bool {
	_, ok := status.Labels[UnsupportedLabel]

	return ok
}

// writtenState is the state and message which the daemon wrote last to a
// node status.
type writtenState struct {
	state   secprofnodestatusapi.ProfileState
	message string
	// profile is the profile of the node status, see WrittenStates.Forget.
	profile types.NamespacedName
}

// WrittenStates keeps the state which the daemon wrote last to each node
// status, keyed by the UID of the profile and the name of the status. Only the
// daemon of a node writes the state of its node status, so the state it wrote
// last is the stored one, while the cache can still return an earlier one.
// Without it, a state which goes back to the one the cache still has, like
// Installed right after an Error, would not be written, see
// SetNodeStatusWithMessage. The zero value is ready to use, see
// WithWrittenStates.
type WrittenStates struct {
	states sync.Map
}

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

	// created is set once this client created the node status, which the
	// cache may not have yet, see getStatus.
	created bool

	// kind is the profile kind, resolved once on construction so that names
	// and labels do not depend on the TypeMeta of pol, which is empty for
	// objects decoded by the uncached typed client.
	kind string

	// written keeps the state this daemon wrote last, see WrittenStates. The
	// state read from the client is used without it.
	written *WrittenStates
}

// ErrNoNodeName is returned if the node name cannot be determined.
var ErrNoNodeName = errors.New("cannot determine node name")

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

// Forget drops the states written for the profile, which is gone. The
// UID of a profile which is not found is unknown, which is part of the key.
func (w *WrittenStates) Forget(profile types.NamespacedName) {
	w.states.Range(func(key, value any) bool {
		if written, ok := value.(writtenState); ok && written.profile == profile {
			w.states.Delete(key)
		}

		return true
	})
}

// WithWrittenStates sets the store of the states which the daemon wrote,
// which a controller keeps for all of its profiles, see WrittenStates.
func (nsf *StatusClient) WithWrittenStates(written *WrittenStates) {
	nsf.written = written
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

// writtenKey is the key of the node status in the WrittenStates.
func (nsf *StatusClient) writtenKey() string {
	return string(nsf.pol.GetUID()) + "/" + nsf.perNodeStatusNamespacedName().String()
}

// recordWritten records the state which got written to the node status.
func (nsf *StatusClient) recordWritten(
	state secprofnodestatusapi.ProfileState, message string,
) {
	if nsf.written != nil {
		nsf.written.states.Store(nsf.writtenKey(), writtenState{
			state: state, message: message, profile: client.ObjectKeyFromObject(nsf.pol),
		})
	}
}

// forgetWritten drops the state written to the node status, which is gone.
func (nsf *StatusClient) forgetWritten() {
	if nsf.written != nil {
		nsf.written.states.Delete(nsf.writtenKey())
	}
}

// currentState returns the state and message of the status, or the ones this
// daemon wrote last, which the cache may not have yet.
func (nsf *StatusClient) currentState(
	status *secprofnodestatusapi.SecurityProfileNodeStatus,
) (state secprofnodestatusapi.ProfileState, message, label string) {
	state = status.Status.Status
	message = status.Status.Message
	label = status.Labels[secprofnodestatusapi.StatusStateLabel]

	if nsf.written == nil {
		return state, message, label
	}

	if value, ok := nsf.written.states.Load(nsf.writtenKey()); ok {
		written, ok := value.(writtenState)
		if ok {
			return written.state, written.message, string(written.state)
		}
	}

	return state, message, label
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
	if err := nsf.createNodeStatus(ctx, legacyState, false); err != nil {
		return false, fmt.Errorf("cannot create node status for %s: %w", nsf.pol.GetName(), err)
	}

	nsf.created = true

	return wasMigrated, nil
}

// getStatus reads the node status through c. The cache may not have a status
// which this client just created yet, so that the reconcile which created it
// can go on to update it. Such a status is read through the reader then, see
// WithAPIReader.
func (nsf *StatusClient) getStatus(
	ctx context.Context, c client.Reader, status *secprofnodestatusapi.SecurityProfileNodeStatus,
) error {
	err := c.Get(ctx, nsf.perNodeStatusNamespacedName(), status)
	if kerrors.IsNotFound(err) && nsf.created && nsf.reader != nil {
		return nsf.reader.Get(ctx, nsf.perNodeStatusNamespacedName(), status)
	}

	return err
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
	}, nsf.retryFinalizerWrite())
}

// retryFinalizerWrite returns the retry condition of a finalizer write, which
// retries a conflict. A profile which is not found gets read once more
// through the API reader, the cache can lag behind. A profile the API reader
// does not find either is gone, so retrying it only holds up the worker.
func (nsf *StatusClient) retryFinalizerWrite() func(error) bool {
	notFoundRetried := false

	return func(err error) bool {
		if kerrors.IsConflict(err) {
			return true
		}

		if kerrors.IsNotFound(err) && nsf.reader != nil && !notFoundRetried {
			notFoundRetried = true

			return true
		}

		return false
	}
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
	}, nsf.retryFinalizerWrite())
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

// MarkUnsupported sets the state and the message of the node status of a node
// which does not support the kind of the profile, and marks the status with
// UnsupportedLabel. A missing status gets created without the finalizer of
// the node, there is nothing on the node to remove before the profile can go
// away, and the garbage collector removes the status along with the profile.
// The finalizer of a node which supported the kind before stays until the
// profile gets deleted. A node which supports the kind again replaces the
// status with a regular one, see Create.
func (nsf *StatusClient) MarkUnsupported(
	ctx context.Context, polState secprofnodestatusapi.ProfileState, message string,
) error {
	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.getStatus(ctx, nsf.client, status)

	switch {
	// A status left over from a deleted profile of the same name gets the
	// owner, the labels and the annotations of this profile, like on Create.
	case kerrors.IsNotFound(err), err == nil && !ownedByProfile(status, nsf.pol.GetUID()):
		if err := nsf.createNodeStatus(ctx, "", true); err != nil {
			return fmt.Errorf("cannot create node status for %s: %w", nsf.pol.GetName(), err)
		}

		nsf.created = true
	case err != nil:
		return fmt.Errorf("fetching node status: %w", err)
	case !IsUnsupported(status):
		if err := nsf.patchUnsupportedLabel(ctx, status, "true"); err != nil {
			return fmt.Errorf("marking node status as unsupported: %w", err)
		}
	}

	return nsf.SetNodeStatusWithMessage(ctx, polState, message)
}

// ClearUnsupported removes the UnsupportedLabel from the node status of a
// node which supports the kind of the profile again, see MarkUnsupported. The
// state goes back to the initial one first, so that the error which told that
// the node does not support the kind is never part of the aggregated state of
// the profile. A missing status has nothing to clear.
func (nsf *StatusClient) ClearUnsupported(ctx context.Context) error {
	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.getStatus(ctx, nsf.client, status)
	if kerrors.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("fetching node status: %w", err)
	}

	if !IsUnsupported(status) {
		return nil
	}

	if err := nsf.SetNodeStatus(ctx, nsf.initialStatus()); err != nil {
		return fmt.Errorf("resetting unsupported node status: %w", err)
	}

	if err := nsf.patchUnsupportedLabel(ctx, status, nil); err != nil {
		return fmt.Errorf("unmarking unsupported node status: %w", err)
	}

	return nil
}

// patchUnsupportedLabel sets the UnsupportedLabel of the status to value, a
// nil value removes it.
func (nsf *StatusClient) patchUnsupportedLabel(
	ctx context.Context, status *secprofnodestatusapi.SecurityProfileNodeStatus, value any,
) error {
	labelPatch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{UnsupportedLabel: value},
		},
	})
	if err != nil {
		return fmt.Errorf("marshaling node status label patch: %w", err)
	}

	return nsf.client.Patch(ctx, status, client.RawPatch(types.MergePatchType, labelPatch))
}

// createNodeStatus creates the node status with all of its labels. A status
// migrated from a legacy status keeps the state of the legacy one, which tells
// for example whether the profile got installed on the node already. The API
// server drops the status of a created object, so the state takes a second
// write, unless an existing status has it already. unsupported marks the
// status with UnsupportedLabel, which an existing status loses otherwise.
func (nsf *StatusClient) createNodeStatus(
	ctx context.Context, legacyState secprofnodestatusapi.ProfileState, unsupported bool,
) error {
	initialStatus := nsf.initialStatus()
	if initialStatus == secprofnodestatusapi.ProfileStatePending && legacyState != "" {
		initialStatus = legacyState
	}

	s := nsf.statusObj(initialStatus)
	if unsupported {
		s.Labels[UnsupportedLabel] = "true"
	}

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
		// The cache may not have the status which the API server has, so it
		// is read through the API reader if there is one.
		var reader client.Reader = nsf.client
		if nsf.reader != nil {
			reader = nsf.reader
		}

		existing := &secprofnodestatusapi.SecurityProfileNodeStatus{}
		if getErr := reader.Get(
			ctx,
			nsf.perNodeStatusNamespacedName(),
			existing,
		); getErr != nil {
			return fmt.Errorf("fetching existing node status: %w", getErr)
		}

		// The status may be left over from a profile of the same name which
		// got deleted, so its owner and labels become the ones of this
		// profile. The garbage collector would delete it otherwise. A status
		// written before the node name moved into the spec gets it as well.
		if !equality.Semantic.DeepEqual(existing.OwnerReferences, s.OwnerReferences) ||
			!labels.SelectorFromSet(s.Labels).Matches(labels.Set(existing.Labels)) ||
			IsUnsupported(existing) != unsupported ||
			existing.Spec.NodeName == "" {
			if existing.Labels == nil {
				existing.Labels = map[string]string{}
			}

			// The annotations of the deleted profile, like the one which
			// tells that the daemon installed its AppArmor policy, do not
			// hold for this one, and neither do the ones of a status of
			// unknown origin.
			if !ownedByProfile(existing, nsf.pol.GetUID()) {
				maps.DeleteFunc(existing.Annotations, func(key, _ string) bool {
					return strings.HasPrefix(key, annotationPrefix)
				})
			}

			maps.Copy(existing.Labels, s.Labels)

			if !unsupported {
				delete(existing.Labels, UnsupportedLabel)
			}

			existing.OwnerReferences = s.OwnerReferences

			if existing.Spec.NodeName == "" {
				existing.Spec.NodeName = nsf.nodeName
			}

			if updateErr := nsf.client.Update(ctx, existing); updateErr != nil {
				return fmt.Errorf("updating existing node status: %w", updateErr)
			}
		}

		s = existing
	}

	if s.Status.Status == initialStatus && s.Status.Message == "" {
		nsf.recordWritten(initialStatus, "")

		return nil
	}

	base := s.DeepCopy()
	s.Status.Status = initialStatus
	s.Status.Message = ""

	if patchErr := nsf.client.Status().Patch(ctx, s, client.MergeFrom(base)); patchErr != nil {
		nsf.forgetWritten()

		return fmt.Errorf("setting initial node status: %w", patchErr)
	}

	nsf.recordWritten(initialStatus, "")

	return nil
}

// ownedByProfile returns true if the controller of the status is the profile
// with the UID.
func ownedByProfile(
	status *secprofnodestatusapi.SecurityProfileNodeStatus, uid types.UID,
) bool {
	owner := metav1.GetControllerOf(status)

	return owner != nil && owner.UID == uid
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
// A profile which is gone has no finalizer left to remove: the finalizer
// which got removed last, like the one shared by all nodes for a partial
// profile, lets it go away while the other nodes still reconcile its
// deletion.
//
// A profile which was partial and got its partial label removed still
// carries the finalizer shared by all nodes for partial profiles, next to
// the ones the nodes added since. Nothing else removes it, so it goes along
// with the finalizer of this node. The finalizers of the other nodes keep the
// profile until they removed it. Like for the legacy finalizer, a node which
// did not add its own finalizer since the promotion yet does not hold the
// profile any more then, so it can go away before that node removed it. A
// profile which gets deleted before any node added its own finalizer is
// released by ReleasePartialFinalizer.
func (nsf *StatusClient) removeFinalizer(ctx context.Context) error {
	finalizers := []string{nsf.finalizerString, nsf.legacyFinalizerString}
	if !nsf.pol.IsPartial() {
		finalizers = append(finalizers, partialProfileFinalizer)
	}

	err := util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		return util.RemoveFinalizers(ctx, c, nsf.pol, finalizers...)
	}, kerrors.IsConflict)

	return client.IgnoreNotFound(err)
}

// ReleasePartialFinalizer removes the finalizer shared by all nodes for partial
// profiles from a profile which got its partial label removed, see
// removeFinalizer. A profile which gets deleted before any node added its own
// finalizer since would keep it forever otherwise. A partial profile is never
// installed, so nothing on the nodes depends on it.
func (nsf *StatusClient) ReleasePartialFinalizer(ctx context.Context) error {
	if nsf.pol.IsPartial() || !controllerutil.ContainsFinalizer(nsf.pol, partialProfileFinalizer) {
		return nil
	}

	err := util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		return util.RemoveFinalizers(ctx, c, nsf.pol, partialProfileFinalizer)
	}, kerrors.IsConflict)

	return client.IgnoreNotFound(err)
}

func (nsf *StatusClient) removeNodeStatus(ctx context.Context, c client.Client) error {
	// the state here is more or less unused, we just care about the name since we're deleting...
	err := c.Delete(ctx, nsf.statusObj(secprofnodestatusapi.ProfileStateTerminating))
	if err != nil && !kerrors.IsNotFound(err) {
		return fmt.Errorf("deleting node status: %w", err)
	}

	nsf.forgetWritten()

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

	err := nsf.getStatus(ctx, nsf.client, &status)
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
// and the message are set already, which the state this daemon wrote last
// tells, see WrittenStates, or else the status read from the cache.
func (nsf *StatusClient) SetNodeStatusWithMessage(
	ctx context.Context,
	polState secprofnodestatusapi.ProfileState,
	message string,
) error {
	message = truncateMessage(message)

	status := &secprofnodestatusapi.SecurityProfileNodeStatus{}

	err := nsf.getStatus(ctx, nsf.client, status)
	if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
		// it's OK if we're about to terminate a profile but it was already gone
		return nil
	} else if err != nil {
		return fmt.Errorf("retrieving the current status: %w", err)
	}

	currentState, currentMessage, currentLabel := nsf.currentState(status)

	if currentLabel != string(polState) {
		// The cached labels can lag behind as well, so the patch sets the
		// label instead of the difference to them.
		labelPatch, err := json.Marshal(map[string]any{
			"metadata": map[string]any{
				"labels": map[string]string{
					secprofnodestatusapi.StatusStateLabel: string(polState),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("marshaling node status label patch: %w", err)
		}

		if err := nsf.client.Patch(
			ctx, status, client.RawPatch(types.MergePatchType, labelPatch),
		); err != nil {
			// The API server may have applied the patch, like on a
			// timeout, so the state written last is unknown now.
			nsf.forgetWritten()

			return fmt.Errorf("updating node status labels: %w", err)
		}
	}

	if currentState == polState && currentMessage == message {
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
		nsf.forgetWritten()

		return fmt.Errorf("updating node status: %w", err)
	}

	nsf.recordWritten(polState, message)

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
	if err := nsf.getStatus(ctx, nsf.client, &status); err != nil {
		return "", fmt.Errorf("getting node status for annotation: %w", err)
	}

	if status.Annotations == nil {
		return "", nil
	}

	return status.Annotations[key], nil
}

// SetAnnotation sets the annotation on the node status of the profile, see
// SetAnnotations.
func (nsf *StatusClient) SetAnnotation(ctx context.Context, key, value string) error {
	return nsf.SetAnnotations(ctx, map[string]string{key: value})
}

// SetAnnotations sets the annotations on the node status of the profile in a
// single update. A conflict with another writer of the status, like
// SetNodeStatus running for the same profile, is retried with the status read
// from the API server, the cache may still return the version which lost.
func (nsf *StatusClient) SetAnnotations(ctx context.Context, annotations map[string]string) error {
	return util.RetryWithFreshReads(ctx, nsf.client, nsf.reader, func(c client.Client) error {
		status := secprofnodestatusapi.SecurityProfileNodeStatus{}
		if err := nsf.getStatus(ctx, c, &status); err != nil {
			return fmt.Errorf("getting node status for annotation update: %w", err)
		}

		if status.Annotations == nil {
			status.Annotations = make(map[string]string, len(annotations))
		}

		changed := false

		for key, value := range annotations {
			if status.Annotations[key] != value {
				status.Annotations[key] = value
				changed = true
			}
		}

		if !changed {
			return nil
		}

		if err := c.Update(ctx, &status); err != nil {
			return fmt.Errorf("updating node status annotation: %w", err)
		}

		return nil
	}, kerrors.IsConflict)
}

// State returns the state of the profile on the node.
func (nsf *StatusClient) State(ctx context.Context) (secprofnodestatusapi.ProfileState, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.getStatus(ctx, nsf.client, &status); err != nil {
		return "", fmt.Errorf("getting node status: %w", err)
	}

	state, _, _ := nsf.currentState(&status)

	return state, nil
}

func (nsf *StatusClient) Matches(
	ctx context.Context, polState secprofnodestatusapi.ProfileState,
) (bool, error) {
	status := secprofnodestatusapi.SecurityProfileNodeStatus{}
	if err := nsf.getStatus(ctx, nsf.client, &status); err != nil {
		if kerrors.IsNotFound(err) && polState == secprofnodestatusapi.ProfileStateTerminating {
			// it's OK if we're about to terminate a profile but it was already gone
			return true, nil
		}

		return false, fmt.Errorf("getting node status for matching: %w", err)
	}

	state, _, _ := nsf.currentState(&status)

	return state == polState, nil
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
