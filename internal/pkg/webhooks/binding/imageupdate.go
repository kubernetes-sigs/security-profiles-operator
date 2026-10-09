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

package binding

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	profilebindingapi "sigs.k8s.io/security-profiles-operator/api/profilebinding/v1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

// imageUpdateValidator rejects image changes of the containers of a running
// pod, if an image specific binding matches the old or the new image. The
// bindings only apply when a pod gets created, so the container would
// otherwise restart with the image of a binding but without its profile, or
// keep the profile bound to its old image. Bindings which apply to no pod,
// because their profile does not exist or never gets installed, are ignored.
type imageUpdateValidator struct {
	// binder tells whether a binding applies to pods, like on their creation.
	binder  *podBinder
	decoder admission.Decoder
	log     logr.Logger
}

// imageChange is the image change of a container.
type imageChange struct {
	container, oldImage, newImage string
}

// changedImages returns the image changes of the init and regular containers.
// The containers of a pod cannot be added, removed or renamed on update.
func changedImages(pod, oldPod *corev1.Pod) []imageChange {
	oldImages := map[string]string{}
	for _, c := range podContainers(oldPod) {
		oldImages[c.Name] = c.Image
	}

	var changes []imageChange

	for _, c := range podContainers(pod) {
		if oldImage, ok := oldImages[c.Name]; ok && oldImage != c.Image {
			changes = append(changes, imageChange{c.Name, oldImage, c.Image})
		}
	}

	return changes
}

// bindsImage returns true if the binding is image specific and matches the
// image.
func bindsImage(pb *profilebindingapi.ProfileBinding, image string) bool {
	return pb.Spec.Image != profilebindingapi.SelectAllContainersImage &&
		util.SameImage(pb.Spec.Image, image)
}

//nolint:gocritic // hugeParam: admission.Handler defines the signature
func (v *imageUpdateValidator) Handle(
	ctx context.Context,
	req admission.Request,
) admission.Response {
	if req.Operation != admissionv1.Update || req.SubResource != "" {
		return admission.Allowed("not a pod update")
	}

	pod := &corev1.Pod{}
	if err := v.decoder.Decode(req, pod); err != nil {
		v.log.Error(err, "failed to decode pod")

		return admission.Errored(http.StatusBadRequest, err)
	}

	oldPod := &corev1.Pod{}
	if err := v.decoder.DecodeRaw(req.OldObject, oldPod); err != nil {
		v.log.Error(err, "failed to decode old pod")

		return admission.Errored(http.StatusBadRequest, err)
	}

	// The bindings do not apply to Windows pods.
	if utils.IsWindowsPod(oldPod) {
		return admission.Allowed("windows pod")
	}

	changes := changedImages(pod, oldPod)
	if len(changes) == 0 {
		return admission.Allowed("images unchanged")
	}

	bindings, err := v.binder.ListProfileBindings(ctx, client.InNamespace(req.Namespace))
	if err != nil {
		v.log.Error(err, "could not list profile bindings")

		return admission.Errored(http.StatusInternalServerError, err)
	}

	lookup := &profileLookup{enabled: map[profilebindingapi.ProfileBindingKind]bool{}}

	// The pod selector of a binding is ignored, because the labels of a
	// running pod can change, so they do not tell whether the binding applied
	// on creation.
	for _, pb := range sortBindings(bindings.Items) {
		for _, change := range changes {
			if !bindsImage(pb, change.oldImage) && !bindsImage(pb, change.newImage) {
				continue
			}

			applies, err := v.binder.bindingApplies(ctx, lookup, pb)
			if err != nil {
				v.log.Error(err, "could not check whether the binding applies", "binding", pb.Name)

				return admission.Errored(http.StatusInternalServerError, err)
			}

			// None of the changes escapes a binding which applies to no pod.
			if !applies {
				break
			}

			return admission.Denied(fmt.Sprintf(
				"the image of container %s cannot change from %s to %s, because profile binding "+
					"%s binds image %s and bindings only apply on pod creation: recreate the pod instead",
				change.container, change.oldImage, change.newImage, pb.Name, pb.Spec.Image,
			))
		}
	}

	return admission.Allowed("no binding matches the changed images")
}

// bindingApplies returns false if the binding applies to no pod, which the
// mutating webhook skips without rejecting the pod, see getProfile: its
// profile does not exist, or it has no status and its kind is disabled, so
// that no daemon ever installs it. A profile which pods use cannot be deleted,
// so a missing profile was not applied to running pods either. The profile is
// read from the cache without waiting for it.
func (p *podBinder) bindingApplies(
	ctx context.Context, lookup *profileLookup, pb *profilebindingapi.ProfileBinding,
) (bool, error) {
	profileKind := pb.Spec.ProfileRef.Kind
	// Profiles are cluster scoped, so the key carries no namespace.
	key := types.NamespacedName{Name: pb.Spec.ProfileRef.Name}

	var err error

	switch profileKind {
	case profilebindingapi.ProfileBindingKindSeccompProfile:
		_, err = lookupProfile(ctx, key, false, p.GetSeccompProfile)
	case profilebindingapi.ProfileBindingKindSelinuxProfile:
		_, err = lookupProfile(ctx, key, false, p.GetSelinuxProfile)
	case profilebindingapi.ProfileBindingKindAppArmorProfile:
		_, err = lookupProfile(ctx, key, false, p.GetAppArmorProfile)
	default:
		// The mutating webhook skips the unsupported kinds.
		return false, nil
	}

	switch {
	case err == nil:
		return true, nil
	case kerrors.IsNotFound(err):
		return false, nil
	case errors.Is(err, ErrProfWithoutStatus):
		return p.cachedProfileKindEnabled(ctx, lookup, profileKind)
	default:
		return false, fmt.Errorf("get %s %s: %w", profileKind, key.Name, err)
	}
}
