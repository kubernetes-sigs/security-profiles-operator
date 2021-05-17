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

package workloadannotator

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	spOwnerKey       = ".metadata.seccompProfileOwner"
	linkedPodsKey    = ".metadata.activeWorkloads"
	reconcileTimeout = 1 * time.Minute
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &PodReconciler{}
}

// A PodReconciler monitors pod changes and links them to SeccompProfiles.
type PodReconciler struct {
	client client.Client
	log    logr.Logger
	record event.Recorder
}

// Name returns the name of the controller.
func (r *PodReconciler) Name() string {
	return "workload-annotator"
}

// SchemeBuilder returns the API scheme of the controller.
func (r *PodReconciler) SchemeBuilder() *scheme.Builder {
	return nil
}

// Healthz is the liveness probe endpoint of the controller.
func (r *PodReconciler) Healthz(*http.Request) error {
	return nil
}

// Namespace scoped
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile reacts to pod events and updates SeccompProfiles if in use or no longer in use by a pod.
func (r *PodReconciler) Reconcile(_ context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(context.Background(), reconcileTimeout)
	defer cancel()

	podID := req.Namespace + "/" + req.Name

	pod := &corev1.Pod{}
	var err error
	if err = r.client.Get(ctx, req.NamespacedName, pod); util.IgnoreNotFound(err) != nil {
		logger.Error(err, "could not get pod")
		return reconcile.Result{}, errors.Wrap(err, "looking up pod in pod reconciler")
	}
	if kerrors.IsNotFound(err) { // this is a pod deletion, so update all seccomp profiles that were using it
		seccompProfiles := &v1alpha1.SeccompProfileList{}
		if err = r.client.List(ctx, seccompProfiles, client.MatchingFields{linkedPodsKey: podID}); err != nil {
			return reconcile.Result{}, errors.Wrap(err, "listing SeccompProfiles for deleted pod")
		}
		for i := range seccompProfiles.Items {
			if err = r.updatePodReferences(ctx, &seccompProfiles.Items[i]); err != nil {
				return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile for deleted pod")
			}
		}
		return reconcile.Result{}, nil
	}
	// pod is being created or updated so ensure it is linked to a seccomp profile
	for _, profileIndex := range getSeccompProfilesFromPod(pod) {
		profileElements := strings.Split(profileIndex, "/")
		profileNamespace := profileElements[1]
		profileName := strings.TrimSuffix(profileElements[2], ".json")
		seccompProfile := &v1alpha1.SeccompProfile{}
		if err := r.client.Get(ctx, util.NamespacedName(profileName, profileNamespace), seccompProfile); err != nil {
			logger.Error(err, "could not get seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "looking up SeccompProfile for new or updated pod")
		}
		if err := r.updatePodReferences(ctx, seccompProfile); err != nil {
			logger.Error(err, "could not update seccomp profile for pod")
			return reconcile.Result{}, errors.Wrap(err, "updating SeccompProfile pod references for new or updated pod")
		}
	}
	return reconcile.Result{}, nil
}

// updatePodReferences updates a SeccompProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferences(ctx context.Context, sp *v1alpha1.SeccompProfile) error {
	linkedPods := &corev1.PodList{}
	profileReference := fmt.Sprintf("operator/%s/%s.json", sp.GetNamespace(), sp.GetName())
	err := r.client.List(ctx, linkedPods, client.MatchingFields{spOwnerKey: profileReference})
	if util.IgnoreNotFound(err) != nil {
		return errors.Wrap(err, "listing pods to update seccompProfile")
	}
	podList := make([]string, len(linkedPods.Items))
	for i := range linkedPods.Items {
		pod := linkedPods.Items[i]
		podList[i] = pod.ObjectMeta.Namespace + "/" + pod.ObjectMeta.Name
	}
	if err := util.Retry(func() error {
		sp.Status.ActiveWorkloads = podList

		updateErr := r.client.Status().Update(ctx, sp)
		if updateErr != nil {
			if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
				return errors.Wrap(err, "retrieving profile")
			}
		}

		return errors.Wrap(updateErr, "updating profile")
	}, util.IsNotFoundOrConflict); err != nil {
		return errors.Wrap(err, "updating SeccompProfile status")
	}
	if len(linkedPods.Items) > 0 {
		if err := util.Retry(func() error {
			return util.AddFinalizer(ctx, r.client, sp, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return errors.Wrap(err, "adding finalizer")
		}
	} else {
		if err := util.Retry(func() error {
			return util.RemoveFinalizer(ctx, r.client, sp, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return errors.Wrap(err, "removing finalizer")
		}
	}
	return nil
}

// getSeccompProfilesFromPod returns a slice of strings representing seccomp profiles required by the pod.
// It looks first at the pod spec level, then in each container and init container, then in the annotations.
func getSeccompProfilesFromPod(pod *corev1.Pod) []string {
	profiles := []string{}
	// try to get profile from pod securityContext
	sc := pod.Spec.SecurityContext
	if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
		profiles = append(profiles, *sc.SeccompProfile.LocalhostProfile)
	}
	// try to get profile(s) from securityContext in pods
	containers := pod.Spec.Containers
	containers = append(containers, pod.Spec.InitContainers...)
	contains := func(a []string, b string) bool {
		for _, s := range a {
			if s == b {
				return true
			}
		}
		return false
	}
	for i := range containers {
		sc := containers[i].SecurityContext
		if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
			profileString := *containers[i].SecurityContext.SeccompProfile.LocalhostProfile
			if !contains(profiles, profileString) {
				profiles = append(profiles, profileString)
			}
		}
	}
	// try to get profile from annotations
	annotation, hasAnnotation := pod.GetAnnotations()[corev1.SeccompPodAnnotationKey]
	if hasAnnotation && strings.HasPrefix(annotation, "localhost/") {
		profileString := strings.TrimPrefix(annotation, "localhost/")
		if !contains(profiles, profileString) {
			profiles = append(profiles, profileString)
		}
	}
	return profiles
}

// isOperatorSeccompProfile checks whether a corev1.SeccompProfile object belongs to the operator.
// SeccompProfiles controlled by the operator are of type "Localhost" and have a path of the form
// "operator/namespace/profile-name.json".
func isOperatorSeccompProfile(sp *corev1.SeccompProfile) bool {
	if sp == nil || sp.Type != "Localhost" {
		return false
	}
	if !strings.HasPrefix(*sp.LocalhostProfile, "operator/") {
		return false
	}
	if !strings.HasSuffix(*sp.LocalhostProfile, ".json") {
		return false
	}
	const pathParts = 3
	return len(strings.Split(*sp.LocalhostProfile, "/")) == pathParts
}
