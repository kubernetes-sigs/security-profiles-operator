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

package recording

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"sigs.k8s.io/security-profiles-operator/api/profilerecording/v1alpha1"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/config"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/webhooks/utils"
)

type defaultImpl struct {
	client  client.Client
	decoder *admission.Decoder
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate -header ../../../../hack/boilerplate/boilerplate.generatego.txt
//counterfeiter:generate . impl
type impl interface {
	GetProfileRecording(ctx context.Context, name, namespace string) (*v1alpha1.ProfileRecording, error)
	ListProfileRecordings(context.Context, ...client.ListOption) (*v1alpha1.ProfileRecordingList, error)
	ListRecordedPods(ctx context.Context, inNs string, selector *metav1.LabelSelector) (*corev1.PodList, error)
	UpdateResource(context.Context, logr.Logger, client.Object, string) error
	UpdateResourceStatus(context.Context, logr.Logger, client.Object, string) error
	DecodePod(admission.Request) (*corev1.Pod, error)
	LabelSelectorAsSelector(*metav1.LabelSelector) (labels.Selector, error)
	GetOperatorNamespace() string
}

func (d *defaultImpl) GetProfileRecording(
	ctx context.Context, name, namespace string,
) (*v1alpha1.ProfileRecording, error) {
	profileRecording := &v1alpha1.ProfileRecording{}
	prName := types.NamespacedName{Name: name, Namespace: namespace}
	if err := d.client.Get(ctx, prName, profileRecording); err != nil {
		return nil, fmt.Errorf("get profile recording: %w", err)
	}
	return profileRecording, nil
}

func (d *defaultImpl) ListProfileRecordings(
	ctx context.Context, opts ...client.ListOption,
) (*v1alpha1.ProfileRecordingList, error) {
	profileRecordings := &v1alpha1.ProfileRecordingList{}
	if err := d.client.List(ctx, profileRecordings, opts...); err != nil {
		return nil, fmt.Errorf("list profile recordings: %w", err)
	}
	return profileRecordings, nil
}

func (d *defaultImpl) ListRecordedPods(
	ctx context.Context,
	inNs string,
	selector *metav1.LabelSelector,
) (*corev1.PodList, error) {
	podList := &corev1.PodList{}

	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("get profile recording: %w", err)
	}

	opts := client.ListOptions{
		LabelSelector: labelSelector,
		Namespace:     inNs,
	}

	if err := d.client.List(ctx, podList, &opts); err != nil {
		return nil, fmt.Errorf("list recorded pods: %w", err)
	}

	return podList, nil
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
	return utils.UpdateResourceStatus(ctx, logger, d.client.Status(), object, name)
}

func (d *defaultImpl) GetOperatorNamespace() string {
	return config.GetOperatorNamespace()
}

//nolint:gocritic
func (d *defaultImpl) DecodePod(req admission.Request) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	if err := d.decoder.Decode(req, pod); err != nil {
		return nil, fmt.Errorf("decode pod: %w", err)
	}
	return pod, nil
}

func (*defaultImpl) LabelSelectorAsSelector(
	ps *metav1.LabelSelector,
) (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(ps)
}
