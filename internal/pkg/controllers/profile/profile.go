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
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"time"

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
)

const (
	// default reconcile timeout
	reconcileTimeout = 1 * time.Minute

	longWait = 1 * time.Minute

	errGetProfile           = "cannot get profile"
	errConfigMapNil         = "config map cannot be nil"
	errConfigMapWithoutName = "config map must have a name"
	errSavingProfile        = "cannot save profile"
	errCreatingOperatorDir  = "cannot create operator directory"

	seccompOperatorSuffix string      = "seccomp/operator"
	filePermissionMode    os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	kubeletSeccompRootPath = "/var/lib/kubelet"

	// DefaultProfilesConfigMapName is the configMap name for the default
	// profiles.
	DefaultProfilesConfigMapName = "default-profiles"

	// DefaultNamespace is the default namespace for the operator deployment.
	DefaultNamespace = "seccomp-operator"
)

// SeccompProfileAnnotation is the annotation on a ConfigMap that specifies its
// intention to be treated as a seccomp profile.
const SeccompProfileAnnotation = "seccomp.security.kubernetes.io/profile"

// isProfile checks if a ConfigMap has been designated as a seccomp profile.
func isProfile(obj runtime.Object) bool {
	r, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return false
	}

	return r.Annotations[SeccompProfileAnnotation] == "true"
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
		})
}

// A Reconciler reconciles seccomp profiles.
type Reconciler struct {
	client client.Client
	log    logr.Logger
}

// Reconcile reconciles a ConfigMap representing a seccomp profile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	profile := &corev1.ConfigMap{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: req.Namespace}, profile); err != nil {
		// Returning an error means we will be requeued implicitly.
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}

	for name, contents := range profile.Data {
		profilePath, err := getProfilePath(name, profile)
		if err != nil {
			logger.Error(err, "cannot get profile path")
			return reconcile.Result{}, err
		}

		if err = saveProfileOnDisk(profilePath, contents); err != nil {
			logger.Error(err, "cannot save profile into disk")
			return reconcile.Result{}, err
		}
	}

	logger.Info("Reconciled profile", "resource version", profile.GetResourceVersion())
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

func getProfilePath(profileName string, cfg *corev1.ConfigMap) (string, error) {
	if cfg == nil {
		return "", errors.New(errConfigMapNil)
	}
	if cfg.ObjectMeta.Name == "" {
		return "", errors.New(errConfigMapWithoutName)
	}

	targetPath := DirTargetPath()
	filePath := path.Join(targetPath,
		filepath.Base(cfg.ObjectMeta.Namespace),
		filepath.Base(cfg.ObjectMeta.Name),
		filepath.Base(profileName))

	return filePath, nil
}

// DirTargetPath returns the default local operator profile root path.
func DirTargetPath() string {
	return path.Join(kubeletSeccompRootPath, seccompOperatorSuffix)
}

func ignoreNotFound(err error) error {
	if kerrors.IsNotFound(err) {
		return nil
	}
	return err
}
