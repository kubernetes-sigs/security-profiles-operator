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

package binding

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/api/profilebinding/v1alpha1"
	seccompprofileapi "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

type defaultImpl struct {
	client  client.Client
	decoder *admission.Decoder
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
//counterfeiter:generate . impl
type impl interface {
	ListProfileBindings(context.Context, ...client.ListOption) (*v1alpha1.ProfileBindingList, error)
	UpdateResource(context.Context, logr.Logger, client.Object, string) error
	UpdateResourceStatus(context.Context, logr.Logger, client.Object, string) error
	SetDecoder(*admission.Decoder)
	DecodePod(admission.Request) (*corev1.Pod, error)
	GetSeccompProfile(context.Context, types.NamespacedName) (*seccompprofileapi.SeccompProfile, error)
}

func (d *defaultImpl) ListProfileBindings(
	ctx context.Context, opts ...client.ListOption,
) (*v1alpha1.ProfileBindingList, error) {
	profileBindings := &v1alpha1.ProfileBindingList{}
	err := d.client.List(ctx, profileBindings, opts...)
	return profileBindings, errors.Wrap(err, "list profile bindings")
}

func (d *defaultImpl) UpdateResource(
	ctx context.Context,
	logger logr.Logger,
	object client.Object,
	name string,
) error {
	return utils.UpdateResource(ctx, logger, d.client, object, name)
}

func (d *defaultImpl) UpdateResourceStatus(
	ctx context.Context,
	logger logr.Logger,
	object client.Object,
	name string,
) error {
	return utils.UpdateResource(ctx, logger, d.client.Status(), object, name)
}

func (d *defaultImpl) SetDecoder(decoder *admission.Decoder) {
	d.decoder = decoder
}

// nolint: gocritic
func (d *defaultImpl) DecodePod(req admission.Request) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := d.decoder.Decode(req, pod)
	return pod, errors.Wrap(err, "decode pod")
}

func (d *defaultImpl) GetSeccompProfile(
	ctx context.Context, key types.NamespacedName,
) (*seccompprofileapi.SeccompProfile, error) {
	seccompProfile := &seccompprofileapi.SeccompProfile{}
	err := d.client.Get(ctx, key, seccompProfile)
	return seccompProfile, errors.Wrap(err, "get seccomp profile")
}
