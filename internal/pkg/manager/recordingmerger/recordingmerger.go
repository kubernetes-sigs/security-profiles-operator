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

package recordingmerger

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	apparmorprofileapi "sigs.k8s.io/security-profiles-operator/api/apparmorprofile/v1alpha1"
	profilerecording1alpha1 "sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	reconcileTimeout = 1 * time.Minute

	errGetRecording       = "cannot get profile recording"
	errMergingRec         = "cannot recorded profiles"
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
	record record.EventRecorder
}

// Name returns the name of the controller.
func (r *PolicyMergeReconciler) Name() string {
	return "policymerger"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *PolicyMergeReconciler) SchemeBuilder() *scheme.Builder {
	return profilerecording1alpha1.SchemeBuilder
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

// Reconcile reconciles a NodeStatus.
func (r *PolicyMergeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	logger := r.log.WithValues("profileRecording", req.Name, "namespace", req.Namespace)
	logger.Info("Reconciling profile recording")

	profileRecording := &profilerecording1alpha1.ProfileRecording{}
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
	profileRecording *profilerecording1alpha1.ProfileRecording,
) error {
	var err error

	switch profileRecording.Spec.Kind {
	case profilerecording1alpha1.ProfileRecordingKindSeccompProfile:
		err = r.mergeSeccompProfiles(ctx, profileRecording)
	case profilerecording1alpha1.ProfileRecordingKindSelinuxProfile:
		err = r.mergeSelinuxProfiles(ctx, profileRecording)
	case profilerecording1alpha1.ProfileRecordingKindAppArmorProfile:
		err = r.mergeAppArmorProfiles(ctx, profileRecording)
	default:
		err = fmt.Errorf("%s: %s", errCannotMergeKind, profileRecording.Spec.Kind)
		r.record.Event(profileRecording, util.EventTypeWarning, reasonCannotMergeKind, err.Error())
	}

	if err != nil {
		return fmt.Errorf("cannot merge profiles: %w", err)
	}

	return err
}

func (r *PolicyMergeReconciler) mergeTypedProfiles(
	ctx context.Context,
	profileRecording *profilerecording1alpha1.ProfileRecording,
	createUpdateMergedProfile createUpdateFn,
	profileItem client.Object,
	listItem client.ObjectList,
) error {
	partialProfiles, err := listPartialProfiles(ctx, r.client, listItem, profileRecording)
	if err != nil {
		return fmt.Errorf("cannot list partial profiles: %w", err)
	}

	if len(partialProfiles) == 0 {
		r.record.Event(profileRecording, util.EventTypeWarning, reasonNoPartialProfiles, errNoPartialProfiles)
		r.log.Info(errNoPartialProfiles)

		return nil
	}

	for cntName, cntPartialProfiles := range partialProfiles {
		r.log.Info("Merging profiles for container", "container", cntName)

		mergedProfile, err := mergeMergeableProfiles(cntPartialProfiles)
		if err != nil {
			return fmt.Errorf("cannot merge partial profiles: %w", err)
		}

		if mergedProfile == nil {
			r.record.Event(profileRecording, util.EventTypeWarning, reasonMergedEmptyProfile, errEmptyMergedProfile)
			r.log.Info(errEmptyMergedProfile)

			return nil
		}

		mergedRecordingName := mergedProfileName(profileRecording.Name, cntPartialProfiles[0])

		res, err := createUpdateMergedProfile(ctx, r.client, profileRecording, mergedRecordingName, mergedProfile)
		if err != nil {
			r.record.Event(profileRecording, util.EventTypeWarning, reasonCannotCreateUpdate, err.Error())

			return fmt.Errorf("cannot create or update merged profile: action:  %w", err)
		}

		r.log.Info("Created/updated profile", "action", res, "name", mergedRecordingName)
	}

	return deletePartialProfiles(ctx, r.client, profileItem, profileRecording)
}

type createUpdateFn func(
	ctx context.Context,
	client client.Client,
	profileRecording *profilerecording1alpha1.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
) (controllerutil.OperationResult, error)

func (r *PolicyMergeReconciler) mergeSeccompProfiles(
	ctx context.Context,
	profileRecording *profilerecording1alpha1.ProfileRecording,
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
	profileRecording *profilerecording1alpha1.ProfileRecording,
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
	profileRecording *profilerecording1alpha1.ProfileRecording,
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
	profileRecording *profilerecording1alpha1.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecording1alpha1.ProfileRecordingKindSeccompProfile,
	)
}

func createUpdateSelinuxProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecording1alpha1.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecording1alpha1.ProfileRecordingKindSelinuxProfile,
	)
}

func createUpdateApparmorProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecording1alpha1.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
) (controllerutil.OperationResult, error) {
	return createUpdateProfile(
		ctx,
		cl,
		profileRecording,
		mergedRecordingName,
		mergedProfiles,
		profilerecording1alpha1.ProfileRecordingKindAppArmorProfile,
	)
}

func createUpdateProfile(
	ctx context.Context,
	cl client.Client,
	profileRecording *profilerecording1alpha1.ProfileRecording,
	mergedRecordingName string,
	mergedProfiles mergeableProfile,
	kind profilerecording1alpha1.ProfileRecordingKind,
) (controllerutil.OperationResult, error) {
	switch kind {
	case profilerecording1alpha1.ProfileRecordingKindSeccompProfile:
		mergedSp := &seccompprofile.SeccompProfile{
			ObjectMeta: *mergedObjectMeta(mergedRecordingName, profileRecording.Name, profileRecording.Namespace),
		}

		mergedProf, ok := mergedProfiles.getProfile().(*seccompprofile.SeccompProfile)
		if !ok {
			return controllerutil.OperationResultNone, errors.New("cannot convert merged profile to SeccompProfile")
		}

		mergedSpec := mergedProf.Spec.DeepCopy()
		mergedSp.Spec = *mergedSpec

		return controllerutil.CreateOrUpdate(ctx, cl, mergedSp,
			func() error {
				mergedSp.Spec = *mergedSpec

				return nil
			},
		)

	case profilerecording1alpha1.ProfileRecordingKindSelinuxProfile:
		mergedSp := &selinuxprofileapi.SelinuxProfile{
			ObjectMeta: *mergedObjectMeta(mergedRecordingName, profileRecording.Name, profileRecording.Namespace),
		}

		mergedProf, ok := mergedProfiles.getProfile().(*selinuxprofileapi.SelinuxProfile)
		if !ok {
			return controllerutil.OperationResultNone, errors.New("cannot convert merged profile to SelinuxProfile")
		}

		mergedSpec := mergedProf.Spec.DeepCopy()
		mergedSp.Spec = *mergedSpec

		return controllerutil.CreateOrUpdate(ctx, cl, mergedSp,
			func() error {
				mergedSp.Spec = *mergedSpec

				return nil
			},
		)
	case profilerecording1alpha1.ProfileRecordingKindAppArmorProfile:
		mergedSp := &apparmorprofileapi.AppArmorProfile{
			ObjectMeta: *mergedObjectMeta(mergedRecordingName, profileRecording.Name, profileRecording.Namespace),
		}

		mergedProf, ok := mergedProfiles.getProfile().(*apparmorprofileapi.AppArmorProfile)
		if !ok {
			return controllerutil.OperationResultNone, errors.New("cannot convert merged profile to AppArmorProfile")
		}

		mergedSpec := mergedProf.Spec.DeepCopy()
		mergedSp.Spec = *mergedSpec

		return controllerutil.CreateOrUpdate(ctx, cl, mergedSp,
			func() error {
				mergedSp.Spec = *mergedSpec

				return nil
			},
		)
	default:
		return controllerutil.OperationResultNone, nil
	}
}
