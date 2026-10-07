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

package recordingmerger

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

// Partial profiles recorded before 1.0 only carry the recording name, while
// the merge and the release of a recording select its partial profiles by the
// recording name and namespace. A recording which was started before an
// upgrade would never merge them, so they are adopted once at startup: every
// recording which may own them still exists then. A recording which may own
// partial profiles that could not be adopted keeps its finalizer, because
// releasing it would orphan them and merging them could add the syscalls of
// another workload to its profile.

const (
	// legacyAdoptionWait is how long a deleted recording waits for the
	// adoption at startup before it is reconciled again.
	legacyAdoptionWait = 2 * time.Second

	// legacyHoldWait is how long a deleted recording which is held for
	// partial profiles recorded before 1.0 waits before it checks them again.
	legacyHoldWait = time.Minute

	// legacyCacheTimeout bounds the wait for the cache to show the adopted
	// partial profiles.
	legacyCacheTimeout = 2 * time.Minute

	// legacyEventProfiles is how many partial profiles an event names.
	legacyEventProfiles = 5

	reasonAmbiguousLegacy string = "AmbiguousLegacyPartialProfiles"
	reasonHeldForLegacy   string = "UnattributedLegacyPartialProfiles"
)

// legacyAdoptionBackoff retries the adoption at startup after errors.
var legacyAdoptionBackoff = wait.Backoff{
	Duration: time.Second,
	Factor:   2,
	Steps:    6,
}

// legacyPartialProfileSelector selects the partial profiles recorded before
// 1.0 by the recordings with this name: the partial profile labels of a
// recording, without the recording namespace.
func legacyPartialProfileSelector(recordingName string) (client.MatchingLabelsSelector, error) {
	selector := labels.NewSelector()

	for key, value := range partialProfileLabels(&profilerecordingapi.ProfileRecording{
		ObjectMeta: metav1.ObjectMeta{Name: recordingName},
	}) {
		op, values := selection.Equals, []string{value}
		if key == profilerecordingapi.ProfileToRecordingNamespaceLabel {
			op, values = selection.DoesNotExist, nil
		}

		requirement, err := labels.NewRequirement(key, op, values)
		if err != nil {
			return client.MatchingLabelsSelector{}, fmt.Errorf(
				"selecting partial profiles recorded before 1.0: %w", err,
			)
		}

		selector = selector.Add(*requirement)
	}

	return client.MatchingLabelsSelector{Selector: selector}, nil
}

// listLegacyPartialProfiles lists the partial profiles of every kind which
// were recorded before 1.0 by a recording with this name and are not being
// deleted.
func listLegacyPartialProfiles(
	ctx context.Context,
	reader client.Reader,
	recordingName string,
) ([]client.Object, error) {
	selector, err := legacyPartialProfileSelector(recordingName)
	if err != nil {
		return nil, err
	}

	var profiles []client.Object

	for _, k := range mergeKinds {
		list := k.newList()
		if err := reader.List(ctx, list, selector); err != nil {
			return nil, fmt.Errorf(
				"listing partial profiles of kind %s recorded before 1.0: %w",
				k.kind,
				err,
			)
		}

		if err := meta.EachListItem(list, func(obj runtime.Object) error {
			prf, ok := obj.(client.Object)
			if !ok {
				return fmt.Errorf("object %T is not a client.Object", obj)
			}

			if prf.GetDeletionTimestamp().IsZero() {
				profiles = append(profiles, prf)
			}

			return nil
		}); err != nil {
			return nil, err
		}
	}

	return profiles, nil
}

// mayOwn returns whether the recording may have recorded the profile. A
// recording which was created after the profile cannot have recorded it.
func mayOwn(recording *profilerecordingapi.ProfileRecording, prf client.Object) bool {
	return !recording.GetCreationTimestamp().After(prf.GetCreationTimestamp().Time)
}

// profileNames names the first profiles for an event.
func profileNames(profiles []client.Object) string {
	names := make([]string, 0, len(profiles))
	for _, prf := range profiles {
		names = append(names, prf.GetName())
	}

	slices.Sort(names)

	if len(names) <= legacyEventProfiles {
		return strings.Join(names, ", ")
	}

	return fmt.Sprintf("%s and %d more",
		strings.Join(names[:legacyEventProfiles], ", "), len(names)-legacyEventProfiles)
}

// apiReader returns the reader of the API server, and the client in tests.
func (r *PolicyMergeReconciler) apiReader() client.Reader {
	if r.reader != nil {
		return r.reader
	}

	return r.client
}

// legacyAdopter adopts the partial profiles recorded before 1.0 once, when
// the manager starts. It runs on the leader, like the merge.
type legacyAdopter struct {
	r *PolicyMergeReconciler
}

// NeedLeaderElection runs the adoption on the leader only.
func (*legacyAdopter) NeedLeaderElection() bool {
	return true
}

// Start adopts the partial profiles recorded before 1.0 and lets the deleted
// recordings be merged afterwards. Errors are logged rather than returned,
// because they must not stop the manager: a recording which may own partial
// profiles that were not adopted is held, see legacyHold.
func (a *legacyAdopter) Start(ctx context.Context) error {
	defer a.r.legacyAdoptionPending.Store(false)

	err := wait.ExponentialBackoffWithContext(
		ctx,
		legacyAdoptionBackoff,
		func(ctx context.Context) (bool, error) {
			if err := a.r.adoptLegacyPartialProfiles(ctx); err != nil {
				a.r.log.Error(
					err,
					"Cannot adopt the partial profiles recorded before 1.0, retrying",
				)

				return false, nil
			}

			return true, nil
		},
	)
	if err != nil {
		a.r.log.Error(err, "Giving up adopting the partial profiles recorded before 1.0")
	}

	return nil
}

// adoptLegacyPartialProfiles labels every partial profile recorded before 1.0
// with the namespace of the only recording which may have recorded it. The
// recordings are listed from the API server: the cache only covers the watched
// namespaces, and a recording outside of them may own a partial profile too.
func (r *PolicyMergeReconciler) adoptLegacyPartialProfiles(ctx context.Context) error {
	reader := r.apiReader()

	recordings := &profilerecordingapi.ProfileRecordingList{}
	if err := reader.List(ctx, recordings); err != nil {
		return fmt.Errorf("listing profile recordings: %w", err)
	}

	byName := map[string][]*profilerecordingapi.ProfileRecording{}

	for i := range recordings.Items {
		recording := &recordings.Items[i]
		byName[recording.GetName()] = append(byName[recording.GetName()], recording)
	}

	var adopted []client.Object

	for name, recordingsWithName := range byName {
		profiles, err := listLegacyPartialProfiles(ctx, reader, name)
		if err != nil {
			return err
		}

		ambiguous := map[*profilerecordingapi.ProfileRecording][]client.Object{}

		for _, prf := range profiles {
			var owners []*profilerecordingapi.ProfileRecording

			for _, recording := range recordingsWithName {
				if mayOwn(recording, prf) {
					owners = append(owners, recording)
				}
			}

			switch len(owners) {
			case 0:
				// Recorded by a recording which is gone: a recording with the
				// same name was created later.
				r.log.Info("No recording may own the partial profile recorded before 1.0",
					"profile", prf.GetName(), "recording", name)
			case 1:
				if err := r.adoptLegacyPartialProfile(ctx, prf, owners[0]); err != nil {
					return err
				}

				adopted = append(adopted, prf)
			default:
				for _, owner := range owners {
					ambiguous[owner] = append(ambiguous[owner], prf)
				}
			}
		}

		for owner, ownerProfiles := range ambiguous {
			r.record.Eventf(
				owner,
				nil,
				util.EventTypeWarning,
				reasonAmbiguousLegacy,
				util.EventActionMerge,
				"Partial profiles recorded before 1.0 may belong to this or another recording named %s, "+
					"set the %s label to the namespace of their recording to merge them: %s",
				name,
				profilerecordingapi.ProfileToRecordingNamespaceLabel,
				profileNames(ownerProfiles),
			)
		}
	}

	if len(adopted) > 0 {
		r.log.Info("Adopted partial profiles recorded before 1.0", "profiles", len(adopted))
	}

	return r.waitForCachedAdoption(ctx, adopted)
}

// adoptLegacyPartialProfile labels a partial profile recorded before 1.0 with
// the namespace of its recording.
func (r *PolicyMergeReconciler) adoptLegacyPartialProfile(
	ctx context.Context,
	prf client.Object,
	recording *profilerecordingapi.ProfileRecording,
) error {
	orig, ok := prf.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("object %T is not a client.Object", prf)
	}

	prfLabels := prf.GetLabels()
	prfLabels[profilerecordingapi.ProfileToRecordingNamespaceLabel] = recording.GetNamespace()
	prf.SetLabels(prfLabels)

	if err := r.client.Patch(ctx, prf, client.MergeFrom(orig)); err != nil {
		return fmt.Errorf("labeling partial profile %s: %w", prf.GetName(), err)
	}

	return nil
}

// waitForCachedAdoption waits until the cache shows the adopted partial
// profiles, so that the merge of a deleted recording, which lists them from
// the cache, does not miss them once the adoption is done.
func (r *PolicyMergeReconciler) waitForCachedAdoption(
	ctx context.Context,
	adopted []client.Object,
) error {
	if len(adopted) == 0 {
		return nil
	}

	err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, legacyCacheTimeout, true,
		func(ctx context.Context) (bool, error) {
			for _, prf := range adopted {
				cached, ok := prf.DeepCopyObject().(client.Object)
				if !ok {
					return false, fmt.Errorf("object %T is not a client.Object", prf)
				}

				if err := r.client.Get(ctx, client.ObjectKeyFromObject(prf), cached); err != nil {
					if client.IgnoreNotFound(err) == nil {
						continue
					}

					// Retried until the timeout.
					return false, nil
				}

				if _, ok := cached.GetLabels()[profilerecordingapi.ProfileToRecordingNamespaceLabel]; !ok {
					return false, nil
				}
			}

			return true, nil
		})
	if err != nil {
		return fmt.Errorf("waiting for the cache to show the adopted partial profiles: %w", err)
	}

	return nil
}

// legacyHold returns how long a deleted recording waits before its partial
// profiles get merged and it gets released: while the partial profiles
// recorded before 1.0 are being adopted at startup, and as long as partial
// profiles recorded before 1.0 exist which it may own but which were not
// adopted, because several recordings with its name may own them. They are
// merged once their recording namespace label is set.
func (r *PolicyMergeReconciler) legacyHold(
	ctx context.Context,
	recording *profilerecordingapi.ProfileRecording,
) (time.Duration, error) {
	if r.legacyAdoptionPending.Load() {
		return legacyAdoptionWait, nil
	}

	profiles, err := listLegacyPartialProfiles(ctx, r.apiReader(), recording.GetName())
	if err != nil {
		return 0, err
	}

	var held []client.Object

	for _, prf := range profiles {
		if mayOwn(recording, prf) {
			held = append(held, prf)
		}
	}

	if len(held) == 0 {
		return 0, nil
	}

	r.record.Eventf(
		recording,
		nil,
		util.EventTypeWarning,
		reasonHeldForLegacy,
		util.EventActionMerge,
		"Waiting for %d partial profiles recorded before 1.0 which may belong to this recording, "+
			"set the %s label to the namespace of their recording or delete them: %s",
		len(held),
		profilerecordingapi.ProfileToRecordingNamespaceLabel,
		profileNames(held),
	)

	return legacyHoldWait, nil
}
