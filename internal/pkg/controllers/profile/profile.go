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
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"sigs.k8s.io/security-profiles-operator/api/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
)

const (
	// default reconcile timeout.
	reconcileTimeout = 1 * time.Minute

	wait = 30 * time.Second

	errGetProfile          = "cannot get profile"
	errSeccompProfileNil   = "seccomp profile cannot be nil"
	errSavingProfile       = "cannot save profile"
	errCreatingOperatorDir = "cannot create operator directory"

	filePermissionMode os.FileMode = 0o644

	// MkdirAll won't create a directory if it does not have the execute bit.
	// https://github.com/golang/go/issues/22323#issuecomment-340568811
	dirPermissionMode os.FileMode = 0o744

	reasonSeccompNotSupported   event.Reason = "SeccompNotSupportedOnNode"
	reasonInvalidSeccompProfile event.Reason = "InvalidSeccompProfile"
	reasonCannotGetProfilePath  event.Reason = "CannotGetSeccompProfilePath"
	reasonCannotSaveProfile     event.Reason = "CannotSaveSeccompProfile"

	reasonSavedProfile event.Reason = "SavedSeccompProfile"

	extJSON = ".json"
)

// Setup adds a controller that reconciles seccomp profiles.
func Setup(mgr ctrl.Manager, l logr.Logger) error {
	const name = "profile"

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&v1alpha1.SeccompProfile{}).
		Complete(&Reconciler{
			client: mgr.GetClient(),
			log:    l,
			record: event.NewAPIRecorder(mgr.GetEventRecorderFor(name)),
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

// Reconcile reconciles a SeccompProfile.
func (r *Reconciler) Reconcile(req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("profile", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	// Pre-check if the node supports seccomp
	if !seccomp.IsSupported() {
		err := errors.New("profile not added")
		logger.Error(err, fmt.Sprintf("node %q does not support seccomp", os.Getenv(config.NodeNameEnvKey)))
		r.record.Event(&v1alpha1.SeccompProfile{},
			event.Warning(reasonSeccompNotSupported, err, os.Getenv(config.NodeNameEnvKey),
				"node does not support seccomp"))

		// Do not requeue (will be requeued if a change to the object is
		// observed, or after the usually very long reconcile timeout
		// configured for the controller manager)
		return reconcile.Result{}, nil
	}

	seccompProfile := &v1alpha1.SeccompProfile{}
	if err := r.client.Get(ctx, req.NamespacedName, seccompProfile); err != nil {
		// Expected to find a SeccompProfile, return an error and requeue
		return reconcile.Result{}, errors.Wrap(ignoreNotFound(err), errGetProfile)
	}
	return r.reconcileSeccompProfile(ctx, seccompProfile, logger)
}

// OutputProfile represents the on-disk form of the SeccompProfile.
type OutputProfile struct {
	DefaultAction seccomp.Action      `json:"defaultAction"`
	Architectures []*v1alpha1.Arch    `json:"architectures,omitempty"`
	Syscalls      []*v1alpha1.Syscall `json:"syscalls,omitempty"`
	Flags         []*v1alpha1.Flag    `json:"flags,omitempty"`
}

func unionSyscalls(baseSyscalls, appliedSyscalls []*v1alpha1.Syscall) []*v1alpha1.Syscall {
	allSyscalls := make(map[seccomp.Action]map[string]bool)
	for _, b := range baseSyscalls {
		allSyscalls[b.Action] = make(map[string]bool)
		for _, n := range b.Names {
			allSyscalls[b.Action][n] = true
		}
	}
	for _, s := range appliedSyscalls {
		if _, ok := allSyscalls[s.Action]; !ok {
			allSyscalls[s.Action] = make(map[string]bool)
		}
		for _, n := range s.Names {
			allSyscalls[s.Action][n] = true
		}
	}
	finalSyscalls := make([]*v1alpha1.Syscall, 0, len(appliedSyscalls)+len(baseSyscalls))
	for action, names := range allSyscalls {
		syscall := v1alpha1.Syscall{Action: action}
		for n := range names {
			syscall.Names = append(syscall.Names, n)
		}
		finalSyscalls = append(finalSyscalls, &syscall)
	}
	return finalSyscalls
}

func (r *Reconciler) mergeBaseProfile(
	ctx context.Context, sp *v1alpha1.SeccompProfile, l logr.Logger,
) (OutputProfile, error) {
	op := OutputProfile{
		DefaultAction: sp.Spec.DefaultAction,
		Architectures: sp.Spec.Architectures,
		Flags:         sp.Spec.Flags,
	}
	baseProfileName := sp.Spec.BaseProfileName
	if baseProfileName == "" {
		op.Syscalls = sp.Spec.Syscalls
		return op, nil
	}
	baseProfile := &v1alpha1.SeccompProfile{}
	if err := r.client.Get(
		ctx, types.NamespacedName{Namespace: sp.ObjectMeta.Namespace, Name: baseProfileName}, baseProfile); err != nil {
		l.Error(err, "cannot retrieve base profile "+baseProfileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return op, errors.Wrap(err, "cannot retrieve base profile")
	}
	op.Syscalls = unionSyscalls(baseProfile.Spec.Syscalls, sp.Spec.Syscalls)
	return op, nil
}

func (r *Reconciler) reconcileSeccompProfile(
	ctx context.Context, sp *v1alpha1.SeccompProfile, l logr.Logger) (reconcile.Result, error) {
	if sp == nil {
		return reconcile.Result{}, errors.New(errSeccompProfileNil)
	}
	profileName := sp.Name

	outputProfile, err := r.mergeBaseProfile(ctx, sp, l)
	if err != nil {
		return reconcile.Result{RequeueAfter: wait}, nil
	}
	profileContent, err := json.Marshal(outputProfile)
	if err != nil {
		l.Error(err, "cannot validate profile "+profileName)
		r.record.Event(sp, event.Warning(reasonInvalidSeccompProfile, err))
		return reconcile.Result{RequeueAfter: wait}, nil
	}

	profilePath, err := GetProfilePath(profileName, sp.ObjectMeta.Namespace, sp.Spec.TargetWorkload)
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
	sp.Status.Path = profilePath
	if err = r.client.Status().Update(ctx, sp); err != nil {
		l.Error(err, "cannot update SeccompProfile status")
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
	if filepath.Ext(profileName) != extJSON {
		profileName += extJSON
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
