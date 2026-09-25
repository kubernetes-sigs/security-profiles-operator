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
	log    logr.Logger
	record util.EventRecorder
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
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=profilerecordings/finalizers,verbs=get;list;watch
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=seccompprofiles,verbs=get;list;watch;create;update;patch;delete;deletecollection
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=selinuxprofiles,verbs=get;list;watch;create;update;patch;delete;deletecollection
// +kubebuilder:rbac:groups=security-profiles-operator.x-k8s.io,resources=apparmorprofiles,verbs=get;list;watch;create;update;patch;delete;deletecollection

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
		if util.IgnoreNotFound(err) == nil {
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

func (r *PolicyMergeReconciler) mergeProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	var err error

	switch profileRecording.Spec.Kind {
	case profilerecordingapi.ProfileRecordingKindSeccompProfile:
		err = r.mergeSeccompProfiles(ctx, profileRecording)
	case profilerecordingapi.ProfileRecordingKindSelinuxProfile:
		err = r.mergeSelinuxProfiles(ctx, profileRecording)
	case profilerecordingapi.ProfileRecordingKindAppArmorProfile:
		err = r.mergeAppArmorProfiles(ctx, profileRecording)
	default:
		err = fmt.Errorf("%s: %s", errCannotMergeKind, profileRecording.Spec.Kind)
		r.record.Eventf(
			profileRecording,
			nil,
			util.EventTypeWarning,
			reasonCannotMergeKind,
			util.EventActionMerge,
			"%s",
			err.Error(),
		)
	}

	if err != nil {
		return fmt.Errorf("cannot merge profiles: %w", err)
	}

	return err
}

func (r *PolicyMergeReconciler) mergeTypedProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
	createUpdateMergedProfile createUpdateFn,
	profileItem client.Object,
	listItem client.ObjectList,
) error {
	partialProfiles, listedProfiles, err := listPartialProfiles(
		ctx,
		r.client,
		listItem,
		profileRecording,
	)
	if err != nil {
		return fmt.Errorf("cannot list partial profiles: %w", err)
	}

	if len(partialProfiles) == 0 {
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

		return nil
	}

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
			return fmt.Errorf("cannot merge partial profiles: %w", err)
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
			ctx, r.client, profileRecording, mergedRecordingName, mergedProfile, coverageAnnotation)
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

				continue
			}

			return fmt.Errorf("cannot create or update merged profile: action:  %w", err)
		}

		r.log.Info("Created/updated profile", "action", res, "name", mergedRecordingName)
	}

	return deletePartialProfiles(ctx, r.client, listedProfiles)
}

type createUpdateFn func(
	ctx context.Context,
	client client.Client,
	profileRecording *profilerecordingapi.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	coverageAnnotation string,
) (controllerutil.OperationResult, error)

func (r *PolicyMergeReconciler) mergeSeccompProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	return r.mergeTypedProfiles(
		ctx,
		profileRecording,
		createUpdateSeccompProfile,
		&seccompprofile.SeccompProfile{},
		&seccompprofile.SeccompProfileList{})
}

func (r *PolicyMergeReconciler) mergeSelinuxProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	return r.mergeTypedProfiles(
		ctx,
		profileRecording,
		createUpdateSelinuxProfile,
		&selinuxprofileapi.SelinuxProfile{},
		&selinuxprofileapi.SelinuxProfileList{})
}

func (r *PolicyMergeReconciler) mergeAppArmorProfiles(
	ctx context.Context,
	profileRecording *profilerecordingapi.ProfileRecording,
) error {
	return r.mergeTypedProfiles(
		ctx,
		profileRecording,
		createUpdateApparmorProfile,
		&apparmorprofileapi.AppArmorProfile{},
		&apparmorprofileapi.AppArmorProfileList{},
	)
}

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
