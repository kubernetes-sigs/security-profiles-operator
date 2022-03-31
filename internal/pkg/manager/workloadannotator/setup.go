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

	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/daemon/metrics"
)

// Setup adds a controller that reconciles the SPOd DaemonSet.
func (r *PodReconciler) Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	met *metrics.Metrics,
) error {
	const name = "pods"
	r.client = mgr.GetClient()
	r.log = ctrl.Log.WithName(r.Name())
	r.record = event.NewAPIRecorder(mgr.GetEventRecorderFor(name))

	// Index Pods using seccomp profiles
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1.Pod{}, spOwnerKey, func(rawObj client.Object) []string {
		pod, ok := rawObj.(*corev1.Pod)
		if !ok {
			return []string{}
		}
		return getSeccompProfilesFromPod(pod)
	}); err != nil {
		return fmt.Errorf("creating pod index: %w", err)
	}

	// Index SeccompProfiles with active pods
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &seccompprofileapi.SeccompProfile{}, linkedPodsKey, func(rawObj client.Object) []string {
			sp, ok := rawObj.(*seccompprofileapi.SeccompProfile)
			if !ok {
				return []string{}
			}
			return sp.Status.ActiveWorkloads
		}); err != nil {
		return fmt.Errorf("creating seccomp profile index: %w", err)
	}

	// Register a special reconciler for pod events
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&corev1.Pod{}).
		WithEventFilter(resource.NewPredicates(hasSeccompProfile)).
		Complete(r)
}

func hasSeccompProfile(obj runtime.Object) bool {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return false
	}

	return len(getSeccompProfilesFromPod(pod)) > 0
}
