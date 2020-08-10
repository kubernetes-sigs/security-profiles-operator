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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	seccomp "github.com/seccomp/containers-golang"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/seccomp-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	longWait = 1 * time.Minute

	errGetProfile          = "cannot get profile"
	errConfigMapNil        = "config map cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	// seccompProfileAnnotation is the annotation on a ConfigMap that specifies
	// its intention to be treated as a seccomp profile.
	seccompProfileAnnotation = "seccomp.security.kubernetes.io/profile"
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

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.ConfigMap{}).
		WithEventFilter(resource.NewPredicates(isProfile)).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor("profile")),
		})
}

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
}

// Reconcile reconciles a ConfigMap representing a seccomp profile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	configMap := &corev1.ConfigMap{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, configMap); err != nil {
		// Returning an error means we will be requeued implicitly.
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}

	for profileName, profileContent := range configMap.Data {
		if err := validateProfile(profileContent); err != nil {
			reason := "cannot validate profile " + profileName
			logger.Error(err, reason)
			r.record.Event(configMap, event.Warning(event.Reason(reason), err))
			return reconcile.Result{}, errors.Wrap(err, reason)
		}

		profilePath, err := GetProfilePath(profileName, configMap)
		if err != nil {
			logger.Error(err, "cannot get profile path")
			r.record.Event(configMap, event.Warning(event.Reason("cannot get profile path"), err))
			return reconcile.Result{}, err
		}

		if err = saveProfileOnDisk(profilePath, profileContent); err != nil {
			logger.Error(err, "cannot save profile into disk")
			r.record.Event(configMap, event.Warning(event.Reason("cannot save profile into disk"), err))
			return reconcile.Result{}, err
		}
	}

	logger.Info("Reconciled profile", "resource version", configMap.GetResourceVersion())
	return reconcile.Result{RequeueAfter: longWait}, nil
}

func saveProfileOnDisk(fileName, contents string) error {
	if err := os.MkdirAll(path.Dir(fileName), dirPermissionMode); err != nil {
		return errors.Wrap(err, errCreatingOperatorDir)
	}

	if err := ioutil.WriteFile(fileName, []byte(contents), filePermissionMode); err != nil {
		return errors.Wrap(err, errSavingProfile)
	}
	return nil
}

// GetProfilePath returns the full path for the provided profile name and config.
func GetProfilePath(profileName string, cfg *corev1.ConfigMap) (string, error) {
	if cfg == nil {
		return "", errors.New(errConfigMapNil)
	}

	return path.Join(
		config.ProfilesRootPath,
		filepath.Base(cfg.ObjectMeta.Namespace),
		filepath.Base(cfg.ObjectMeta.Name),
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
