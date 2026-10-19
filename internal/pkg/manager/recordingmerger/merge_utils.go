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
	"errors"
	"fmt"
	"slices"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilebase "sigs.k8s.io/security-profiles-operator/api/profilebase/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

func mergedObjectMeta(profileName, recordingName, namespace string) *metav1.ObjectMeta {
	return &metav1.ObjectMeta{
		Name: profileName,
		Labels: map[string]string{
			profilerecordingapi.ProfileToRecordingLabel:          recordingName,
			profilerecordingapi.ProfileToRecordingNamespaceLabel: namespace,
		},
	}
}

func mergeMergeableProfiles(profiles []mergeableProfile) (mergeableProfile, error) {
	if len(profiles) == 0 {
		return nil, errors.New("cannot merge empty list of profiles")
	}

	base := profiles[0]
	if len(profiles) == 1 {
		return base, nil
	}

	mergeSlice := profiles[1:]
	for i := range mergeSlice {
		err := base.merge(mergeSlice[i])
		if err != nil {
			return nil, fmt.Errorf("failed to merge profile %s: %w", mergeSlice[i].GetName(), err)
		}
	}

	return base, nil
}

type perContainerMergeableProfiles map[string][]mergeableProfile

// partialProfileLabels selects the partial profiles of the recording.
func partialProfileLabels(recording *profilerecordingapi.ProfileRecording) client.MatchingLabels {
	return client.MatchingLabels{
		profilerecordingapi.ProfileToRecordingLabel:          recording.Name,
		profilerecordingapi.ProfileToRecordingNamespaceLabel: recording.Namespace,
		profilebase.ProfilePartialLabel:                      "true",
	}
}

// eachPartialProfile lists the partial profiles of the recording of the list
// type and calls fn for each of them.
func eachPartialProfile(
	ctx context.Context,
	cli client.Reader,
	list client.ObjectList,
	recording *profilerecordingapi.ProfileRecording,
	fn func(client.Object) error,
) error {
	if err := cli.List(ctx, list, partialProfileLabels(recording)); err != nil {
		return fmt.Errorf("listing partial profiles for %s: %w", recording.Name, err)
	}

	if err := meta.EachListItem(list, func(obj runtime.Object) error {
		clientObj, ok := obj.(client.Object)
		if !ok {
			return fmt.Errorf("object %T is not a client.Object", obj)
		}

		return fn(clientObj)
	}); err != nil {
		return fmt.Errorf("iterating over partial profiles: %w", err)
	}

	return nil
}

// hasPartialProfiles returns whether the recording has partial profiles of
// the list type which are not being deleted.
func hasPartialProfiles(
	ctx context.Context,
	cli client.Reader,
	list client.ObjectList,
	recording *profilerecordingapi.ProfileRecording,
) (bool, error) {
	found := false

	err := eachPartialProfile(ctx, cli, list, recording, func(obj client.Object) error {
		found = found || obj.GetDeletionTimestamp().IsZero()

		return nil
	})

	return found, err
}

// listPartialProfiles returns the partial profiles of the recording grouped by
// container, and a copy of every listed partial profile for the cleanup after
// the merge.
func listPartialProfiles(
	ctx context.Context,
	cli client.Client,
	list client.ObjectList,
	recording *profilerecordingapi.ProfileRecording,
) (perContainerMergeableProfiles, []client.Object, error) {
	partialProfiles := make(perContainerMergeableProfiles)

	var listed []client.Object

	if err := eachPartialProfile(ctx, cli, list, recording, func(obj client.Object) error {
		copied, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("copy of %T is not a client.Object", obj)
		}

		listed = append(listed, copied)

		partialPrf, err := newMergeableProfile(obj)
		if err != nil {
			return fmt.Errorf(
				"failed to create mergeable profile for %s: %w", obj.GetName(), err,
			)
		}

		// A partial profile without container cannot be merged, it is only
		// cleaned up.
		containerID := getContainerID(obj)
		if containerID == "" {
			return nil
		}

		partialProfiles[containerID] = append(partialProfiles[containerID], partialPrf)

		return nil
	}); err != nil {
		return nil, nil, err
	}

	return partialProfiles, listed, nil
}

func MergeProfiles(
	profiles []client.Object,
) (client.Object, error) {
	mergeables := make([]mergeableProfile, len(profiles))

	for i, profile := range profiles {
		mergeable, err := newMergeableProfile(profile)
		if err != nil {
			return nil, err
		}

		mergeables[i] = mergeable
	}

	merged, err := mergeMergeableProfiles(mergeables)
	if err != nil {
		return nil, err
	}

	return merged.getProfile(), nil
}

// MergeIntoStored returns a copy of the stored profile with the rules of the
// desired one added, and the state of the desired one. The other attributes
// of the stored profile, like the default action of a seccomp profile, stay
// the same, the user may have changed them.
func MergeIntoStored(stored, desired client.Object) (client.Object, error) {
	storedCopy, ok := stored.DeepCopyObject().(client.Object)
	if !ok {
		return nil, fmt.Errorf("copy %T: not a client.Object", stored)
	}

	desiredCopy, ok := desired.DeepCopyObject().(client.Object)
	if !ok {
		return nil, fmt.Errorf("copy %T: not a client.Object", desired)
	}

	merged, err := MergeProfiles([]client.Object{storedCopy, desiredCopy})
	if err != nil {
		return nil, err
	}

	SpecBaseOf(merged).State = SpecBaseOf(desired).State

	return merged, nil
}

// NormalizeProfile normalizes a profile's internal representation to match
// the format produced by the merger library. For SeccompProfiles, this
// converts multi-name syscall entries to single-name-per-entry format.
// For AppArmorProfiles, string slices are sorted, capabilities are
// lower-cased as the API requires and duplicate capabilities and ptrace
// accesses are removed.
func NormalizeProfile(obj client.Object) error {
	switch p := obj.(type) {
	case *seccompprofile.SeccompProfile:
		return normalizeSeccompProfile(p)
	case *apparmorprofileapi.AppArmorProfile:
		normalizeAppArmorProfile(p)
	}

	return nil
}

func normalizeSeccompProfile(sp *seccompprofile.SeccompProfile) error {
	syscalls, err := util.UnionSyscalls(sp.Spec.Syscalls, nil)
	if err != nil {
		return fmt.Errorf("normalizing syscalls: %w", err)
	}

	sp.Spec.Syscalls = syscalls
	sp.Spec.Architectures = unionArchitectures(sp.Spec.Architectures, nil)

	return nil
}

func normalizeAppArmorProfile(ap *apparmorprofileapi.AppArmorProfile) {
	a := &ap.Spec.Abstract

	if a.Executable != nil {
		slices.Sort(a.Executable.AllowedExecutables)
		slices.Sort(a.Executable.AllowedLibraries)
	}

	if a.Filesystem != nil {
		slices.Sort(a.Filesystem.ReadOnlyPaths)
		slices.Sort(a.Filesystem.WriteOnlyPaths)
		slices.Sort(a.Filesystem.ReadWritePaths)
	}

	if a.Capability != nil {
		a.Capability.AllowedCapabilities = util.LowerCapabilities(a.Capability.AllowedCapabilities)
	}

	if a.Ptrace != nil && a.Ptrace.AllowedAccess != nil {
		slices.Sort(a.Ptrace.AllowedAccess)
		a.Ptrace.AllowedAccess = slices.Compact(a.Ptrace.AllowedAccess)
	}
}

// SpecBaseOf returns the base spec of the profile, or an empty one for an
// object which is no profile.
func SpecBaseOf(obj client.Object) *profilebase.SpecBase {
	switch prf := obj.(type) {
	case *seccompprofile.SeccompProfile:
		return &prf.Spec.SpecBase
	case *selinuxprofileapi.SelinuxProfile:
		return &prf.Spec.SpecBase
	case *apparmorprofileapi.AppArmorProfile:
		return &prf.Spec.SpecBase
	default:
		return &profilebase.SpecBase{}
	}
}

func getContainerID(prf client.Object) string {
	labels := prf.GetLabels()
	if labels == nil {
		return ""
	}

	return labels[profilerecordingapi.ProfileToContainerLabel]
}

// deletePartialProfiles deletes the provided partial profiles. It only deletes
// the listed objects, so that a partial profile which was created after the
// listing, for example by another pod of the recording, is kept for the next
// merge.
func deletePartialProfiles(ctx context.Context, cli client.Client, profiles []client.Object) error {
	var errs []error

	for _, prf := range profiles {
		uid := prf.GetUID()

		err := cli.Delete(ctx, prf, client.Preconditions{UID: &uid})
		if err != nil && !kerrors.IsNotFound(err) && !kerrors.IsConflict(err) {
			errs = append(errs, fmt.Errorf("deleting partial profile %s: %w", prf.GetName(), err))
		}
	}

	return errors.Join(errs...)
}

func newMergeableProfile(obj client.Object) (mergeableProfile, error) {
	switch obj := obj.(type) {
	case *seccompprofile.SeccompProfile:
		return &mergeableSeccompProfile{SeccompProfile: *obj}, nil
	case *selinuxprofileapi.SelinuxProfile:
		return &MergeableSelinuxProfile{SelinuxProfile: *obj}, nil
	case *apparmorprofileapi.AppArmorProfile:
		return &mergeableAppArmorProfile{AppArmorProfile: *obj}, nil
	default:
		return nil, fmt.Errorf("cannot convert %T to mergeableProfile", obj)
	}
}

type mergeableProfile interface {
	client.Object

	merge(profile mergeableProfile) error
	getProfile() client.Object
}

type mergeableSeccompProfile struct {
	seccompprofile.SeccompProfile
}

func (sp *mergeableSeccompProfile) merge(other mergeableProfile) error {
	otherSP, ok := other.(*mergeableSeccompProfile)
	if !ok {
		return fmt.Errorf("cannot merge SeccompProfile with %T", other)
	}

	syscalls, err := util.UnionSyscalls(sp.Spec.Syscalls, otherSP.Spec.Syscalls)
	if err != nil {
		return fmt.Errorf("merging syscalls: %w", err)
	}

	sp.Spec.Syscalls = syscalls
	sp.Spec.Architectures = unionArchitectures(sp.Spec.Architectures, otherSP.Spec.Architectures)

	return nil
}

// unionArchitectures returns the sorted union of the architectures. The
// partial profiles recorded on nodes of different architectures only list the
// architecture of their node each.
func unionArchitectures(a, b []seccompprofile.Arch) []seccompprofile.Arch {
	if len(a) == 0 && len(b) == 0 {
		return a
	}

	union := slices.Concat(a, b)
	slices.Sort(union)

	return slices.Compact(union)
}

func (sp *mergeableSeccompProfile) getProfile() client.Object {
	return &sp.SeccompProfile
}

type MergeableSelinuxProfile struct {
	selinuxprofileapi.SelinuxProfile
}

func (sp *MergeableSelinuxProfile) getProfile() client.Object {
	return &sp.SelinuxProfile
}

// merge adds the allow rules of other. The other attributes, like the
// inherited policies, are the same for all partial profiles of a recording and
// stay the ones of sp.
func (sp *MergeableSelinuxProfile) merge(other mergeableProfile) error {
	otherSP, ok := other.(*MergeableSelinuxProfile)
	if !ok {
		return fmt.Errorf("cannot merge selinuxProfile with %T", other)
	}

	sp.Spec.Allow = addAllow(sp.Spec.Allow, otherSP.Spec.Allow)

	return nil
}

func addAllow(union, additional selinuxprofileapi.Allow) selinuxprofileapi.Allow {
	// A profile without allow rules has none after a round trip.
	if union == nil && len(additional) > 0 {
		union = make(selinuxprofileapi.Allow, len(additional))
	}

	for labelKey, permMap := range additional {
		if _, ok := union[labelKey]; !ok {
			union[labelKey] = make(
				map[selinuxprofileapi.ObjectClassKey]selinuxprofileapi.PermissionSet,
			)
		}

		for objClass, perms := range permMap {
			allPerms := map[string]bool{}
			for _, havePerm := range union[labelKey][objClass] {
				allPerms[havePerm] = true
			}

			for _, newPerm := range perms {
				_, ok := allPerms[newPerm]
				if !ok {
					union[labelKey][objClass] = append(union[labelKey][objClass], newPerm)
					allPerms[newPerm] = true
				}
			}
		}
	}

	return union
}
