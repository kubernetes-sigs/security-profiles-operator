/*
Copyright 2020 The Kubernetes Authors.

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

package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/containers/common/pkg/seccomp"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	seccompoperatorv1alpha1 "sigs.k8s.io/seccomp-operator/api/v1alpha1"
	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	wait = 30 * time.Second

	errGetProfile          = "cannot get profile"
	errConfigMapNil        = "config map cannot be nil"
	errSeccompProfileNil   = "seccomp profile cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	// seccompProfileAnnotation is the annotation on a ConfigMap that specifies
	// its intention to be treated as a seccomp profile.
	seccompProfileAnnotation = "seccomp.security.kubernetes.io/profile"

	reasonSeccompNotSupported   event.Reason = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile event.Reason = "InvalidSeccompProfile"
	reasonCannotGetProfilePath  event.Reason = "CannotGetSeccompProfilePath"
	reasonCannotSaveProfile     event.Reason = "CannotSaveSeccompProfile"

	reasonSavedProfile event.Reason = "SavedSeccompProfile"
)

// isProfile checks if a ConfigMap has been designated as a seccomp profile.
func isProfile(obj runtime.Object) bool {
	r, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}

	return r.Annotations[seccompProfileAnnotation] == "true"
}

// Setup adds a controller that reconciles seccomp profiles.
func Setup(mgr ctrl.Manager, l logr.Logger) error {
	const name = "profile"

	if err := ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(isProfile)).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("profile")),
			save:   saveProfileOnDisk,
		}); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&seccompoperatorv1alpha1.SeccompProfile{}).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("profile")),
			save:   saveProfileOnDisk,
		})
}

type saver func(string, []byte) error

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
	save   saver
}

// Reconcile reconciles a SeccompProfile or a ConfigMap representing a seccomp profile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Look for the SeccompProfile Kind first
	seccompProfile := &seccompoperatorv1alpha1.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		logger.Error(err, "unable to fetch SeccompProfile")
		seccompProfile = nil
	}
	// If no SeccompProfile, look for a ConfigMap
	configMap := &corev1.ConfigMap{}
	if seccompProfile == nil {
		if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, configMap); err != nil {
			// Returning an error means we will be requeued implicitly.
			return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
		}
	}

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		r.record.Event(seccompProfile,
			event.Warning(reasonSeccompNotSupported, err, os.Getenv(config.NodeNameEnvKey),
				"node does not support seccomp"))

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	if seccompProfile != nil {
		return r.reconcileSeccompProfile(seccompProfile, logger)
	}

	return r.reconcileConfigMap(configMap, logger)
}

func (r *Reconciler) reconcileSeccompProfile(
	sp *seccompoperatorv1alpha1.SeccompProfile, l logr.Logger) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errors.New(errSeccompProfileNil)
	}
	profileName := sp.Name

	profileContent, err := json.Marshal(sp.Spec)
	if err != nil {
		l.Error(err, "cannot validate profile "+profileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	profilePath, err := GetProfilePath(profileName, sp.ObjectMeta.Namespace, config.CustomProfilesDirectoryName)
	if err != nil {
		l.Error(err, "cannot get profile path")
		r.record.Event(sp, event.Warning(reasonCannotGetProfilePath, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	if err = r.save(profilePath, profileContent); err != nil {
		l.Error(err, "cannot save profile into disk")
		r.record.Event(sp, event.Warning(reasonCannotSaveProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	l.Info(
		"Reconciled profile from SeccompProfile",
		"resource version", sp.GetResourceVersion(),
		"name", sp.GetName(),
	)
	r.record.Event(sp, event.Normal(reasonSavedProfile, "Successfully saved profile to disk"))
	return reconcile.Result{}, nil
}

func (r *Reconciler) reconcileConfigMap(cm *corev1.ConfigMap, l logr.Logger) (reconcile.Result, error) {
	if cm == nil {
		return reconcile.Result{}, errors.New(errConfigMapNil)
	}
	for profileName, profileContent := range cm.Data {
		if err := validateProfile(profileContent); err != nil {
			l.Error(err, "cannot validate profile "+profileName)
			r.record.Event(cm, event.Warning(reasonInvalidSeccompProfile, err))

			// it might be possible that other profiles in the cm are
			// valid
			continue
		}

		profilePath, err := GetProfilePath(profileName, cm.ObjectMeta.Namespace, cm.ObjectMeta.Name)
		if err != nil {
			l.Error(err, "cannot get profile path")
			r.record.Event(cm, event.Warning(reasonCannotGetProfilePath, err))
			return reconcile.Result{RequeueAfter: wait}, nil
		}

		if err = r.save(profilePath, []byte(profileContent)); err != nil {
			l.Error(err, "cannot save profile into disk")
			r.record.Event(cm, event.Warning(reasonCannotSaveProfile, err))
			return reconcile.Result{RequeueAfter: wait}, nil
		}
		if err = r.save(profilePath, []byte(profileContent)); err != nil {
			l.Error(err, "cannot save profile into disk")
			r.record.Event(cm, event.Warning(reasonCannotSaveProfile, err))
			return reconcile.Result{RequeueAfter: wait}, nil
		}
	}
	l.Info(
		"Reconciled profile from ConfigMap",
		"resource version", cm.GetResourceVersion(),
		"name", cm.GetName(),
	)
	r.record.Event(cm, event.Normal(reasonSavedProfile, "Successfully saved profile to disk"))
	return reconcile.Result{}, nil
}

func saveProfileOnDisk(fileName string, contents []byte) error {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return errors.Wrap(err, errCreatingOperatorDir)
	}

	if err := ioutil.WriteFile(fileName, contents, filePermissionMode); err != nil {
		return errors.Wrap(err, errSavingProfile)
	}
	return nil
}

// GetProfilePath returns the full path for the provided profile name and config.
func GetProfilePath(profileName, namespace, subdir string) (string, error) {
	if filepath.Ext(profileName) == "" {
		profileName += ".json"
	}
	return path.Join(
		config.ProfilesRootPath,
		filepath.Base(namespace),
		filepath.Base(subdir),
		filepath.Base(profileName),
	), nil
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}

// validateProfile does a basic validation for the provided seccomp profile
// string.
func validateProfile(content string) error {
	profile := &seccomp.Seccomp{}
	if err := json.Unmarshal([]byte(content), &profile); err != nil {
		return errors.Wrap(err, "decoding seccomp profile")
	}

	// TODO: consider further validation steps
	return nil
}
