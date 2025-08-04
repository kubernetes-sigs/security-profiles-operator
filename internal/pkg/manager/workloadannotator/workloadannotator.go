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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	selinuxprofileapi "sigs.k8s.io/security-profiles-operator/api/selinuxprofile/v1alpha2"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/controller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
)

const (
	spOwnerKey        = ".metadata.seccompProfileOwner"
	seOwnerKey        = ".metadata.selinuxProfileOwner"
	linkedPodsKey     = ".metadata.activeWorkloads"
	StatusToProfLabel = "spo.x-k8s.io/profile-id"
	reconcileTimeout  = 1 * time.Minute
	pathParts         = 2
)

// NewController returns a new empty controller instance.
func NewController() controller.Controller {
	return &PodReconciler{}
}

// A PodReconciler monitors pod changes and links them to SeccompProfiles.
type PodReconciler struct {
	client client.Client
	log    logr.Logger
	record record.EventRecorder
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

// Reconcile reacts to pod events and updates SeccompProfiles or SelinuxProfiles if in use or no longer in use by a pod.
func (r *PodReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	logger := r.log.WithValues("pod", req.Name, "namespace", req.Namespace)

	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()

	podID := req.Namespace + "/" + req.Name

	pod := &corev1.Pod{}

	var err error
	//nolint:gocritic // It's intended to ignore the not found error
	if err = r.client.Get(ctx, req.NamespacedName, pod); util.IgnoreNotFound(err) != nil {
		logger.Error(err, "could not get pod")

		return reconcile.Result{}, fmt.Errorf("looking up pod in pod reconciler: %w", err)
	}

	if errors.IsNotFound(err) { // this is a pod deletion, so update all seccomp/selinux profiles that were using it
		seccompProfiles := &seccompprofileapi.SeccompProfileList{}
		selinuxProfiles := &selinuxprofileapi.SelinuxProfileList{}

		if err = r.client.List(ctx, seccompProfiles, client.MatchingFields{linkedPodsKey: podID}); err != nil {
			return reconcile.Result{}, fmt.Errorf("listing SeccompProfiles for deleted pod: %w", err)
		}

		if err = r.client.List(ctx, selinuxProfiles, client.MatchingFields{linkedPodsKey: podID}); err != nil {
			return reconcile.Result{}, fmt.Errorf("listing SelinuxProfiles for deleted pod: %w", err)
		}

		for i := range seccompProfiles.Items {
			if err = r.updatePodReferencesForSeccomp(ctx, &seccompProfiles.Items[i]); err != nil {
				return reconcile.Result{}, fmt.Errorf("updating SeccompProfile for deleted pod: %w", err)
			}
		}

		for j := range selinuxProfiles.Items {
			if err = r.updatePodReferencesForSelinux(ctx, &selinuxProfiles.Items[j]); err != nil {
				return reconcile.Result{}, fmt.Errorf("updating SelinuxProfile for deleted pod: %w", err)
			}
		}

		return reconcile.Result{}, nil
	}

	// pod is being created or updated so ensure it is linked to a seccomp/selinux profile
	for _, profileIndex := range getSeccompProfilesFromPod(pod) {
		profileElements := strings.Split(profileIndex, "/")
		if len(profileElements) != pathParts {
			continue
		}

		profileNamespace := "" // It is a cluster wide profile.
		profileName := strings.TrimSuffix(profileElements[1], ".json")
		seccompProfile := &seccompprofileapi.SeccompProfile{}

		if err := r.client.Get(ctx, util.NamespacedName(profileName, profileNamespace), seccompProfile); err != nil {
			logger.Error(err, "could not get seccomp profile for pod")

			return reconcile.Result{}, fmt.Errorf("looking up SeccompProfile for new or updated pod: %w", err)
		}

		if err := r.updatePodReferencesForSeccomp(ctx, seccompProfile); err != nil {
			logger.Error(err, "could not update seccomp profile for pod")

			return reconcile.Result{}, fmt.Errorf("updating SeccompProfile pod references for new or updated pod: %w", err)
		}
	}

	// pod is being created or updated so ensure it is linked to a selinux profile
	for _, profileIndex := range getSelinuxProfilesFromPod(ctx, r, pod) {
		profileSuffix := "_" + ".process"
		profileName := strings.TrimSuffix(profileIndex, profileSuffix)

		selinuxProfile := &selinuxprofileapi.SelinuxProfile{}
		if err := r.client.Get(ctx, util.NamespacedName(profileName, ""), selinuxProfile); err != nil {
			logger.Error(err, "could not get selinux profile for pod")

			return reconcile.Result{}, fmt.Errorf("looking up SelinuxProfile for new or updated pod: %w", err)
		}

		if err := r.updatePodReferencesForSelinux(ctx, selinuxProfile); err != nil {
			logger.Error(err, "could not update selinux profile for pod")

			return reconcile.Result{}, fmt.Errorf("updating SelinuxProfile pod references for new or updated pod: %w", err)
		}
	}

	return reconcile.Result{}, nil
}

// updatePodReferencesForSeccomp updates a SeccompProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferencesForSeccomp(ctx context.Context, sp *seccompprofileapi.SeccompProfile) error {
	linkedPods := &corev1.PodList{}
	profileReference := fmt.Sprintf("operator/%s.json", sp.GetName())

	err := r.client.List(ctx, linkedPods, client.MatchingFields{spOwnerKey: profileReference})
	if util.IgnoreNotFound(err) != nil {
		return fmt.Errorf("listing pods to update seccompProfile: %w", err)
	}

	podList := make([]string, len(linkedPods.Items))

	for i := range linkedPods.Items {
		pod := linkedPods.Items[i]
		podList[i] = pod.Namespace + "/" + pod.Name
	}

	if err := util.Retry(func() error {
		sp.Status.ActiveWorkloads = podList

		updateErr := r.client.Status().Update(ctx, sp)
		if updateErr != nil {
			if err := r.client.Get(ctx, util.NamespacedName(sp.GetName(), sp.GetNamespace()), sp); err != nil {
				return fmt.Errorf("retrieving profile: %w", err)
			}

			return fmt.Errorf("updating profile: %w", updateErr)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating SeccompProfile status: %w", err)
	}

	if len(linkedPods.Items) > 0 {
		if err := util.Retry(func() error {
			return util.AddFinalizer(ctx, r.client, sp, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}
	} else {
		if err := util.Retry(func() error {
			return util.RemoveFinalizer(ctx, r.client, sp, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return fmt.Errorf("removing finalizer: %w", err)
		}
	}

	return nil
}

// updatePodReferencesForSelinux updates a SelinuxProfile with the identifiers of pods using it and ensures
// it has a finalizer indicating it is in use to prevent it from being deleted.
func (r *PodReconciler) updatePodReferencesForSelinux(ctx context.Context, se *selinuxprofileapi.SelinuxProfile) error {
	linkedPods := &corev1.PodList{}
	profileReference := se.GetPolicyUsage()

	err := r.client.List(ctx, linkedPods, client.MatchingFields{seOwnerKey: profileReference})
	if util.IgnoreNotFound(err) != nil {
		return fmt.Errorf("listing pods to update selinuxProfile: %w", err)
	}

	podList := make([]string, len(linkedPods.Items))

	for i := range linkedPods.Items {
		pod := linkedPods.Items[i]
		podList[i] = pod.Namespace + "/" + pod.Name
	}

	if err := util.Retry(func() error {
		se.Status.ActiveWorkloads = podList
		updateErr := r.client.Status().Update(ctx, se)
		if updateErr != nil {
			if err := r.client.Get(ctx, util.NamespacedName(se.GetName(), se.GetNamespace()), se); err != nil {
				return fmt.Errorf("retrieving profile: %w", err)
			}

			return fmt.Errorf("updating profile: %w", updateErr)
		}

		return nil
	}, util.IsNotFoundOrConflict); err != nil {
		return fmt.Errorf("updating SelinuxProfile status: %w", err)
	}

	if len(linkedPods.Items) > 0 {
		if err := util.Retry(func() error {
			return util.AddFinalizer(ctx, r.client, se, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return fmt.Errorf("adding finalizer: %w", err)
		}
	} else {
		if err := util.Retry(func() error {
			return util.RemoveFinalizer(ctx, r.client, se, util.HasActivePodsFinalizerString)
		}, util.IsNotFoundOrConflict); err != nil {
			return fmt.Errorf("removing finalizer: %w", err)
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

	for i := range containers {
		sc := containers[i].SecurityContext
		if sc != nil && isOperatorSeccompProfile(sc.SeccompProfile) {
			profileString := *containers[i].SecurityContext.SeccompProfile.LocalhostProfile
			if !util.Contains(profiles, profileString) {
				profiles = append(profiles, profileString)
			}
		}
	}
	// try to get profile from annotations
	annotation, hasAnnotation := pod.GetAnnotations()[corev1.SeccompPodAnnotationKey]
	if hasAnnotation && strings.HasPrefix(annotation, "localhost/") {
		profileString := strings.TrimPrefix(annotation, "localhost/")
		spCheck := &corev1.SeccompProfile{
			Type:             "Localhost",
			LocalhostProfile: &profileString,
		}

		if !util.Contains(profiles, profileString) && isOperatorSeccompProfile(spCheck) {
			profiles = append(profiles, profileString)
		}
	}

	return profiles
}

// getSelinuxProfilesFromPod returns a slice of strings representing selinux profiles required by the pod.
// It looks first at the pod spec level, then in each container.
func getSelinuxProfilesFromPod(ctx context.Context, r *PodReconciler, pod *corev1.Pod) []string {
	profiles := []string{}
	// try to get profile from pod securityContext
	sc := pod.Spec.SecurityContext
	if sc != nil {
		if isOperatorSelinuxType(ctx, r, sc.SELinuxOptions, "") {
			profiles = append(profiles, sc.SELinuxOptions.Type)
		}
	}
	// try to get profile(s) from securityContext in containers
	containers := pod.Spec.Containers
	containers = append(containers, pod.Spec.InitContainers...)

	for i := range containers {
		sc := containers[i].SecurityContext
		if sc != nil {
			if isOperatorSelinuxType(ctx, r, sc.SELinuxOptions, "") {
				profileString := containers[i].SecurityContext.SELinuxOptions.Type
				if !util.Contains(profiles, profileString) {
					profiles = append(profiles, profileString)
				}
			}
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

	return len(strings.Split(*sp.LocalhostProfile, "/")) == pathParts
}

// isOperatorSelinuxType checks whether Selinux Type is created by the operator.
// Selinux Type controlled by the operator has the form
// "selinuxprofilename_namespace.process".
func isOperatorSelinuxType(ctx context.Context, r *PodReconciler, se *corev1.SELinuxOptions, ns string) bool {
	if se == nil {
		return false
	}

	if se.Type == "" {
		return false
	}

	suffix := "_" + ".process"
	selinuxProfileName := strings.TrimSuffix(se.Type, suffix)

	if selinuxProfileName != se.Type {
		selinuxProfile := &selinuxprofileapi.SelinuxProfile{}

		err := r.client.Get(ctx, util.NamespacedName(strings.TrimSuffix(se.Type, suffix), ns), selinuxProfile)
		if err != nil {
			return false
		}

		_, hasLabel := selinuxProfile.GetLabels()[StatusToProfLabel]

		return hasLabel
	}

	return false
}
