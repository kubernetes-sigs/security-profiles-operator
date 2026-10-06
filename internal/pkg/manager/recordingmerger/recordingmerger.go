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
	"net/http"
	"slices"
	"time"

	"github.com/go-logr/logr"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1"
	profilerecordingapi "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	reconcileTimeout = 1 * time.Minute

	errGetRecording       = "cannot get profile recording"
	errMergingRec         = "cannot merge recorded profiles"
	errCannotMergeKind    = "cannot merge profiles of kind"
	errNoPartialProfiles  = "no partial profiles to merge"
	errEmptyMergedProfile = "merged profile is empty"

	reasonCannotMergeKind    string = "KindNotSupportedForMerge"
	reasonCannotCreateUpdate string = "CannotCreateUpdateMergedProfile"
	reasonMergedEmptyProfile string = "MergedEmptyProfile"
	reasonNoPartialProfiles  string = "NoPartialProfiles"
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &PolicyMergeReconciler{}
}

// A PolicyMergeReconciler monitors profilerecordings and merges policies recorded by those.
type PolicyMergeReconciler struct {
	client client.Client
	reader client.Reader
	log    logr.Logger
	record util.EventRecorder
}

// readerClient is a client which reads from the API server instead of the
// cache, so that a retry after a conflict sees the object which won.
type readerClient struct {
	client.Client

	reader client.Reader
}

func (c *readerClient) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption,
) error {
	return c.reader.Get(ctx, key, obj, opts...)
}

// writeClient returns the client for the writes which retry conflicts. Its
// reads bypass the cache, which may still return the object a conflict was
// about.
func (r *PolicyMergeReconciler) writeClient() client.Client {
	if r.reader == nil {
		return r.client
	}

	return &readerClient{Client: r.client, reader: r.reader}
}

// Name returns the name of the controller.
func (r *PolicyMergeReconciler) Name() string {
	return "policymerger"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *PolicyMergeReconciler) SchemeBuilder() runtime.SchemeBuilder {
	return profilerecordingapi.SchemeBuilder
}

// Healthz is the liveness probe endpoint of the controller.
func (r *PolicyMergeReconciler) Healthz(*http.Request) error {
	return nil
}

// Security Profiles Operator RBAC permissions to manage SelinuxProfile
//nolint:lll // required for kubebuilder
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update;patch;delete

// Reconcile reconciles a NodeStatus.
func (r *PolicyMergeReconciler) Reconcile(
	ctx context.Context,
	req reconcile.Request,
) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("profileRecording", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling profile recording")

	profileRecording := &profilerecordingapi.ProfileRecording{}
	if err := r.client.Get(ctx, req.NamespacedName, profileRecording); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("%s: %w", errGetRecording, err)
	}

	if !profileRecording.GetDeletionTimestamp().IsZero() { // object is being deleted
		logger.Info("Is being deleted, will check if there are policies to be merged")

		if err := r.mergeProfiles(ctx, profileRecording); err != nil {
			return reconcile.Result{}, fmt.Errorf("%s: %w", errMergingRec, err)
		}

		return reconcile.Result{}, nil
	}

	// We don't really care until the recording is being deleted
	return reconcile.Result{}, nil
}

// mergeKind is a kind of profiles which a recording can record.
type mergeKind struct {
	kind         profilerecordingapi.ProfileRecordingKind
	createUpdate createUpdateFn
	newList      func() client.ObjectList
}

// mergeKinds are all kinds of partial profiles which a recording can have.
// The kind of a recording can change while partial profiles of the former
// kind exist, so the partial profiles of every kind get merged, not only the
// ones of the current kind.
var mergeKinds = []mergeKind{
	{
		kind:         profilerecordingapi.ProfileRecordingKindSeccompProfile,
		createUpdate: createUpdateSeccompProfile,
		newList:      func() client.ObjectList { return &seccompprofile.SeccompProfileList{} },
	},
	{
		kind:         profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		createUpdate: createUpdateSelinuxProfile,
		newList:      func() client.ObjectList { return &selinuxprofileapi.SelinuxProfileList{} },
	},
	{
		kind:         profilerecordingapi.ProfileRecordingKindAppArmorProfile,
		createUpdate: createUpdateApparmorProfile,
		newList:      func() client.ObjectList { return &apparmorprofileapi.AppArmorProfileList{} },
	},
}

func (r *PolicyMergeReconciler) mergeProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	if !slices.ContainsFunc(mergeKinds, func(k mergeKind) bool {
		return k.kind == profileRecording.Spec.Kind
	}) {
		// The partial profiles of the supported kinds still get merged, so
		// that the recording can go.
		r.record.Eventf(
			profileRecording,
			nil,
			util.EventTypeWarning,
			reasonCannotMergeKind,
			util.EventActionMerge,
			"%s: %s",
			errCannotMergeKind,
			profileRecording.Spec.Kind,
		)
	}

	found := false

	for _, k := range mergeKinds {
		merged, err := r.mergeTypedProfiles(ctx, profileRecording, k.createUpdate, k.newList())
		if err != nil {
			return fmt.Errorf("cannot merge profiles of kind %s: %w", k.kind, err)
		}

		found = found || merged
	}

	if !found {
		r.record.Eventf(
			profileRecording,
			nil,
			util.EventTypeWarning,
			reasonNoPartialProfiles,
			util.EventActionMerge,
			"%s",
			errNoPartialProfiles,
		)
		r.log.Info(errNoPartialProfiles)
	}

	return r.releaseRecording(ctx, profileRecording)
}

// releaseRecording removes the finalizer which keeps the recording until its
// partial profiles are merged, once no partial profile of any kind is left.
// Only the merger removes it, because only the merger checks the partial
// profiles of every kind. The partial profiles are listed from the API server,
// because the cache may not show the deletion of the just merged ones yet. A
// recording which keeps the finalizer is reconciled again once one of its
// partial profiles is gone, see Setup.
func (r *PolicyMergeReconciler) releaseRecording(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	if !controllerutil.ContainsFinalizer(
		profileRecording,
		profilerecordingapi.RecordingHasUnmergedProfiles,
	) {
		return nil
	}

	reader := client.Reader(r.client)
	if r.reader != nil {
		reader = r.reader
	}

	for _, k := range mergeKinds {
		left, err := hasPartialProfiles(ctx, reader, k.newList(), profileRecording)
		if err != nil {
			return fmt.Errorf("cannot list partial profiles of kind %s: %w", k.kind, err)
		}

		if left {
			return nil
		}
	}

	recording := &profilerecordingapi.ProfileRecording{}
	recording.SetName(profileRecording.GetName())
	recording.SetNamespace(profileRecording.GetNamespace())

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return util.RemoveFinalizer(
			ctx,
			r.writeClient(),
			recording,
			profilerecordingapi.RecordingHasUnmergedProfiles,
		)
	})
	if client.IgnoreNotFound(err) != nil {
		return fmt.Errorf("cannot release recording: %w", err)
	}

	return nil
}

// mergeTypedProfiles merges the partial profiles of the list type and deletes
// them. It returns whether there were partial profiles.
func (r *PolicyMergeReconciler) mergeTypedProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
	createUpdateMergedProfile createUpdateFn,
	listItem client.ObjectList,
) (bool, error) {
	partialProfiles, listedProfiles, err := listPartialProfiles(
		ctx,
		r.client,
		listItem,
		profileRecording,
	)
	if err != nil {
		return false, fmt.Errorf("cannot list partial profiles: %w", err)
	}

	if len(listedProfiles) == 0 {
		return false, nil
	}

	// The partial profiles of a skipped container are kept, so that their
	// recorded data is not lost.
	skipped := map[string]bool{}

	for cntName, cntPartialProfiles := range partialProfiles {
		r.log.Info("Merging profiles for container", "container", cntName)

		// Informational only; empty for non-seccomp kinds.
		coverageAnnotation, err := seccompCoverageAnnotation(cntPartialProfiles)
		if err != nil {
			// The current coverage schema contains only JSON-supported types, so
			// this error is theoretical unless the schema changes.
			r.log.Error(err, "Cannot compute syscall coverage", "container", cntName)

			coverageAnnotation = ""
		}

		mergedProfile, err := mergeMergeableProfiles(cntPartialProfiles)
		if err != nil {
			return true, fmt.Errorf("cannot merge partial profiles: %w", err)
		}

		if mergedProfile == nil {
			r.record.Eventf(
				profileRecording,
				nil,
				util.EventTypeWarning,
				reasonMergedEmptyProfile,
				util.EventActionMerge,
				"%s",
				errEmptyMergedProfile,
			)
			r.log.Info(errEmptyMergedProfile, "container", cntName)

			// Defensive only: mergeMergeableProfiles returns a nil profile just
			// with a non-nil error, which is handled above. If that ever
			// changes, skip only this container, because the remaining ones
			// still need to be merged and their partial profiles cleaned up.
			continue
		}

		mergedRecordingName := mergedProfileName(profileRecording.Name, cntPartialProfiles[0])

		r.log.V(1).
			Info("Computed syscall coverage", "container", cntName, "coverage", coverageAnnotation)

		res, err := createUpdateMergedProfile(
			ctx, r.writeClient(), profileRecording, mergedRecordingName, mergedProfile,
			coverageAnnotation,
		)
		if err != nil {
			r.record.Eventf(
				profileRecording,
				nil,
				util.EventTypeWarning,
				reasonCannotCreateUpdate,
				util.EventActionMerge,
				"%s",
				err.Error(),
			)

			// Retrying cannot resolve the conflict, so skip the container.
			if errors.Is(err, util.ErrProfileOwnedByOtherRecording) {
				r.log.Error(err, "Skipping merged profile", "container", cntName)

				skipped[cntName] = true

				continue
			}

			return true, fmt.Errorf("cannot create or update merged profile: action:  %w", err)
		}

		r.log.Info("Created/updated profile", "action", res, "name", mergedRecordingName)
	}

	toDelete := slices.DeleteFunc(listedProfiles, func(obj client.Object) bool {
		return skipped[getContainerID(obj)]
	})

	return true, deletePartialProfiles(ctx, r.client, toDelete)
}

type createUpdateFn func(
	ctx context.Context,
	client client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	coverageAnnotation string,
) (controllerutil.OperationResult, error)

func createUpdateSeccompProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	coverageAnnotation string,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecordingapi.ProfileRecordingKindSeccompProfile,
		coverageAnnotation,
	)
}

func createUpdateSelinuxProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	coverageAnnotation string,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecordingapi.ProfileRecordingKindSelinuxProfile,
		coverageAnnotation,
	)
}

func createUpdateApparmorProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	coverageAnnotation string,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecordingapi.ProfileRecordingKindAppArmorProfile,
		coverageAnnotation,
	)
}

// mergeRetryBackoff is used to retry writing a merged profile if another
// writer, like the profile recorder of a node or another merge, changed or
// created it concurrently.
var mergeRetryBackoff = wait.Backoff{
	Steps:    10,
	Duration: 10 * time.Millisecond,
	Factor:   1.5,
	Jitter:   0.5,
}

// isWriteConflict returns true if the write lost against a concurrent writer.
func isWriteConflict(err error) bool {
	return kerrors.IsConflict(err) || kerrors.IsAlreadyExists(err)
}

// newProfileObject returns an empty profile of the kind with the meta data of
// a merged profile, or nil for unsupported kinds.
func newProfileObject(
	kind profilerecordingapi.ProfileRecordingKind,
	mergedRecordingName string,
	profileRecording *profilerecordingapi.ProfileRecording,
) client.Object {
	meta := *mergedObjectMeta(mergedRecordingName, profileRecording.Name, profileRecording.Namespace)

	switch kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		return &seccompprofile.SeccompProfile{ObjectMeta: meta}
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
		return &selinuxprofileapi.SelinuxProfile{ObjectMeta: meta}
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		return &apparmorprofileapi.AppArmorProfile{ObjectMeta: meta}
	default:
		return nil
	}
}

// setMergedSpec sets the spec of the merged profile on the object.
func setMergedSpec(obj client.Object, merged mergeableProfile) error {
	switch o := obj.(type) {
	case *seccompprofile.SeccompProfile:
		p, ok := merged.getProfile().(*seccompprofile.SeccompProfile)
		if !ok {
			return errors.New("cannot convert merged profile to SeccompProfile")
		}

		o.Spec = *p.Spec.DeepCopy()
	case *selinuxprofileapi.SelinuxProfile:
		p, ok := merged.getProfile().(*selinuxprofileapi.SelinuxProfile)
		if !ok {
			return errors.New("cannot convert merged profile to SelinuxProfile")
		}

		o.Spec = *p.Spec.DeepCopy()
	case *apparmorprofileapi.AppArmorProfile:
		p, ok := merged.getProfile().(*apparmorprofileapi.AppArmorProfile)
		if !ok {
			return errors.New("cannot convert merged profile to AppArmorProfile")
		}

		o.Spec = *p.Spec.DeepCopy()
	default:
		return fmt.Errorf("cannot set merged spec on %T", obj)
	}

	return nil
}

// mergeInto merges the provided partial profiles into the freshly fetched
// object. The partial profiles get deleted after each merge and the profile
// recorder may write into the same profile, so the existing profile has to
// be kept. Profiles created before the recording belong to a previous
// recording with the same name and get replaced.
func mergeInto(
	obj client.Object,
	partial mergeableProfile,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	partialObj, ok := partial.getProfile().DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("copy %T: not a client.Object", partial.getProfile())
	}

	// Merge into a copy, because a retry after a conflict starts over.
	merged, err := newMergeableProfile(partialObj)
	if err != nil {
		return fmt.Errorf("cannot create mergeable profile: %w", err)
	}

	existingCreated := obj.GetCreationTimestamp()
	recordingCreated := profileRecording.GetCreationTimestamp()

	if obj.GetResourceVersion() != "" && !existingCreated.Before(&recordingCreated) {
		existingObj, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			return fmt.Errorf("copy %T: not a client.Object", obj)
		}

		existing, err := newMergeableProfile(existingObj)
		if err != nil {
			return fmt.Errorf("cannot create mergeable profile: %w", err)
		}

		if err := merged.merge(existing); err != nil {
			return fmt.Errorf("failed to merge existing profile %s: %w", obj.GetName(), err)
		}
	}

	return setMergedSpec(obj, merged)
}

// createUpdateProfile merges the partial profiles into the merged profile of
// the recording. The merge happens on the freshly fetched profile within the
// write, so that concurrent writers do not lose each other's changes, and the
// write gets retried if it lost against one of them.
func createUpdateProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	kind profilerecordingapi.ProfileRecordingKind,
	coverageAnnotation string,
) (res controllerutil.OperationResult, err error) {
	if newProfileObject(kind, mergedRecordingName, profileRecording) == nil {
		return controllerutil.OperationResultNone, nil
	}

	err = retry.OnError(mergeRetryBackoff, isWriteConflict, func() error {
		obj := newProfileObject(kind, mergedRecordingName, profileRecording)

		var writeErr error

		res, writeErr = controllerutil.CreateOrUpdate(ctx, cl, obj, func() error {
			if err := util.CheckRecordingOwner(
				obj, profileRecording.Name, profileRecording.Namespace,
			); err != nil {
				return fmt.Errorf("check merged profile owner: %w", err)
			}

			if err := mergeInto(obj, mergedProfiles, profileRecording); err != nil {
				return err
			}

			// The coverage is only computed for seccomp profiles.
			if kind == profilerecordingapi.ProfileRecordingKindSeccompProfile {
				setSyscallCoverageAnnotation(obj, coverageAnnotation)
			}

			return nil
		})

		return writeErr
	})

	return res, err
}
